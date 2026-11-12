"""Durable local handover history, separate from the mutable resume checkpoint.

Completed records are write-once files. A public, hash-linked journal records
checkpoint digests. Retained checkpoints detect missing completed epochs and
modified linked rows. Whole-log rollback needs an external retained head; this
is not protection from a privileged host rewriting history.
"""

import hashlib
import json
import os
import copy
from pathlib import Path
import re

from guardian_service import atomic_write
from .approval import canonical
from .policy import policy_epoch


DOMAIN = b'ElementsFederationHistory/v1\x00'
MAX_EVENTS = 100_000


def stable_state(state):
    result = copy.deepcopy({key: value for key, value in state.items() if key != 'updated_at'})
    if isinstance(result.get('target'), dict):
        # Endpoint/token refresh is a runtime concern, not authorization
        # evidence. The signed public policy remains fully committed.
        result['target'].pop('institutions', None)
    return result


class RotationHistory:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.completed = self.directory / 'completed'
        self.completed.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.events_path = self.directory / 'events.jsonl'
        self.events = self._read_events()

    def _read_events(self):
        if not self.events_path.exists():
            return []
        events, previous = [], '0' * 64
        with self.events_path.open() as stream:
            for line in stream:
                if len(line) > 8192 or len(events) >= MAX_EVENTS:
                    raise ValueError('rotation history exceeds sandbox bound')
                item = json.loads(line)
                payload = item['payload']
                digest = hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()
                if (item['hash'] != digest or payload['previous_hash'] != previous
                        or payload['sequence'] != len(events) + 1):
                    raise ValueError('rotation journal is truncated or inconsistent')
                previous = digest
                events.append(item)
        return events

    @staticmethod
    def _identity(rotation_id):
        if not isinstance(rotation_id, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', rotation_id) is None:
            raise ValueError('invalid archived rotation ID')
        return rotation_id

    def archive(self, state):
        if state['stage'] != 'complete':
            raise ValueError('only completed rotations may enter completed history')
        rotation_id = self._identity(state['id'])
        payload = stable_state(state)
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        path = self.completed / (rotation_id + '.json')
        if path.exists():
            existing = json.loads(path.read_text())
            if (existing.get('version') != 1 or existing.get('digest') != digest
                    or existing.get('state') != payload):
                raise ValueError('completed rotation history cannot be replaced')
            return digest
        # A single coordinator owns this history under the settlement lock.
        # Atomic replacement only publishes a complete fsynced new record.
        atomic_write(path, {'version': 1, 'digest': digest, 'state': payload})
        return digest

    def record(self, state):
        digest = hashlib.sha256(canonical(stable_state(state))).hexdigest()
        if state['stage'] == 'complete':
            self.archive(state)
        if self.events and self.events[-1]['payload']['checkpoint_hash'] == digest:
            return
        target = state.get('target', {}).get('policy', {}).get('policy_version')
        payload = {'sequence': len(self.events) + 1, 'previous_hash': self.events[-1]['hash'] if self.events else '0' * 64,
                   'rotation_id': state['id'], 'stage': state['stage'], 'genesis_hash': state['genesis_hash'],
                   'source_policy_version': state['source_policy']['policy_version'], 'target_policy_version': target,
                   'checkpoint_hash': digest}
        item = {'payload': payload, 'hash': hashlib.sha256(DOMAIN + canonical(payload)).hexdigest()}
        descriptor = os.open(self.events_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, 'ab') as stream:
            stream.write(canonical(item) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.events.append(item)

    def summaries(self, expected_policy=None, genesis_hash=None):
        result = []
        for path in self.completed.glob('*.json'):
            value = json.loads(path.read_text())
            state = value['state']
            if (path.stem != self._identity(state['id']) or value.get('version') != 1
                    or value['digest'] != hashlib.sha256(canonical(state)).hexdigest()
                    or state['stage'] != 'complete'):
                raise ValueError('completed rotation archive is inconsistent')
            source = state['source_policy']['policy_version']
            target = state['target']['policy']['policy_version']
            if policy_epoch(target) != policy_epoch(source) + 1:
                raise ValueError('archived federation epoch is inconsistent')
            result.append({'id': state['id'], 'state': 'complete', 'source_policy_version': source,
                           'target_policy_version': target, 'genesis_hash': state['genesis_hash'],
                           'created_at': state['created_at'], 'archive_hash': value['digest'],
                           'migration_txids': list(state['confirmed_migrations'])})
        result.sort(key=lambda record: policy_epoch(record['target_policy_version']))
        if result and policy_epoch(result[0]['source_policy_version']) != 1:
            raise ValueError('completed rotation history is missing its initial epoch')
        for previous, current in zip(result, result[1:]):
            if (previous['target_policy_version'] != current['source_policy_version']
                    or previous['genesis_hash'] != current['genesis_hash']):
                raise ValueError('completed rotation history has a gap or conflicting epoch')
        if expected_policy is not None:
            endpoint = result[-1]['target_policy_version'] if result else 'sandbox-v1'
            if endpoint != expected_policy:
                raise ValueError('completed rotation history does not reach the retained checkpoint epoch')
        if genesis_hash is not None and any(item['genesis_hash'] != genesis_hash for item in result):
            raise ValueError('completed rotation history differs from the retained checkpoint genesis')
        archives = {item['id']: item['archive_hash'] for item in result}
        for event in self.events:
            payload = event['payload']
            if payload['stage'] == 'complete' and archives.get(payload['rotation_id']) != payload['checkpoint_hash']:
                raise ValueError('completed journal event is missing its matching archive')
        return result

#!/usr/bin/env python3
"""Select and control one existing local demo, preserving its chain and keys."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlsplit

from export_review import ROOT
from verify import OwnedProcess, process_identity, runtime_snapshot, signal_identity

sys.path.insert(0, str(ROOT / 'test' / 'functional'))
from settlement.runtime import load_config, save_config


KIND = 'elements-threshold-audit-demo'
DEFAULT_REGISTRY = Path('/tmp') / f'elements-audit-demo-{os.getuid()}.json'


def validate_runtime(directory):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('runtime must be an existing real directory')
    directory = directory.resolve()
    if directory.stat().st_mode & 0o077:
        raise ValueError('runtime directory must be private (mode 0700)')
    ready = load_config(directory / 'ready.json')
    config = load_config(directory / 'adapter.json')
    load_config(directory / 'launcher.json')
    url = urlsplit(ready['url'])
    if (url.scheme != 'http' or url.hostname not in {'127.0.0.1', 'localhost'}
            or not url.port or url.username or url.password or url.query or url.fragment
            or url.path != '/'):
        raise ValueError('demo URL must be a plain loopback HTTP origin')
    if (type(ready['pid']) is not int or ready['pid'] <= 0
            or len(bytes.fromhex(ready['genesis_hash'])) != 32):
        raise ValueError('invalid runtime readiness identity')
    return directory, ready, config


def select_runtime(directory, registry=DEFAULT_REGISTRY):
    directory, _, _ = validate_runtime(directory)
    registry = Path(registry)
    if registry.exists() or registry.is_symlink():
        if load_config(registry).get('kind') != KIND:
            raise ValueError('refusing to replace an unrelated registry file')
    save_config(registry, {'kind': KIND, 'runtime': str(directory)})
    return directory


def selected_runtime(registry=DEFAULT_REGISTRY):
    value = load_config(registry)
    if value.get('kind') != KIND:
        raise ValueError('unknown demo registry')
    return Path(value['runtime'])


def owner_identity(directory, ready):
    """A stale ready PID is never authority to signal another process."""
    pid = ready['pid']
    identity = process_identity(pid)
    if identity is None:
        return None
    try:
        process = Path('/proc') / str(pid)
        args = (process / 'cmdline').read_bytes().split(b'\0')
        module = args.index(b'-m')
        if (module not in (1, 2, 3) or args[module + 1] != b'settlement.sandbox'
                or any(flag not in {b'-u', b'-B'} for flag in args[1:module])
                or Path(os.readlink(process / 'exe')).resolve() != Path(sys.executable).resolve()
                or Path(os.readlink(process / 'cwd')).resolve() != ROOT.resolve()):
            return None
        locations = [Path(os.fsdecode(args[index + 1])).resolve() for index, value in enumerate(args[:-1])
                     if value in {b'--resume', b'--directory'}]
        if locations != [directory]:
            return None
        if process_identity(pid) == identity:
            return identity
    except (OSError, ValueError, IndexError):
        pass
    return None


def processes(directory, ready):
    result = runtime_snapshot(directory, 0)
    owner = owner_identity(directory, ready)
    if owner is not None:
        result[ready['pid']] = owner
    return result, owner


def app_ready(url):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url + 'api/session', timeout=2) as response:
            return response.status == 200
    except OSError:
        return False


def status(directory):
    directory, ready, config = validate_runtime(directory)
    found, owner = processes(directory, ready)
    roles = {'app': 0, 'node': 0, 'audit_guardians': 0, 'institution_signers': 0}
    for pid in found:
        try:
            args = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if pid == ready['pid'] and owner is not None:
            roles['app'] += 1
        elif b'settlement.treasury' in args:
            roles['institution_signers'] += 1
        elif any(value.endswith(b'/guardian_service.py') for value in args):
            roles['audit_guardians'] += 1
        elif any(value.endswith(b'/elementsd') for value in args):
            roles['node'] += 1
    return {'runtime': str(directory), 'state': 'running' if owner is not None else 'orphaned' if found else 'stopped',
            'app_ready': owner is not None and app_ready(ready['url']),
            'wallet': ready['url'] + 'wallet', 'guardian': ready['url'] + 'guardian',
            'policy_version': config.get('policy_version', 'sandbox-v1'),
            'process_count': len(found), 'roles': roles,
            'credentials_file': str(directory / 'credentials.json'),
            **({'mesh': ready['mesh']} if ready.get('mesh') else {})}


@contextmanager
def control_lock(directory):
    descriptor = os.open(directory / '.manager.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('another manager is controlling this runtime') from None
        yield
    finally:
        os.close(descriptor)


def stop(directory, timeout=120):
    directory, ready, _ = validate_runtime(directory)
    with control_lock(directory):
        found, owner = processes(directory, ready)
        if owner is not None:
            signal_identity(ready['pid'], owner, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        while found:
            # Let the coordinator drain requests and stop its own children.
            # Only remaining orphans are signalled directly after owner exit.
            if owner_identity(directory, ready) is None:
                for pid, identity in found.items():
                    signal_identity(pid, identity, signal.SIGTERM)
            if time.monotonic() >= deadline:
                raise RuntimeError('graceful stop deadline exceeded; runtime data remains intact')
            time.sleep(.15)
            found, _ = processes(directory, ready)
    return status(directory)


def start(directory, timeout=120):
    directory, ready, _ = validate_runtime(directory)
    with control_lock(directory):
        found, owner = processes(directory, ready)
        if owner is not None:
            return status(directory)  # Idempotent; never start a second chain.
        if found:
            raise RuntimeError('orphaned runtime services exist; run stop before start')
        env = dict(os.environ)
        env['PYTHONPATH'] = os.pathsep.join([str(ROOT / 'contrib' / 'threshold-audit'),
                                           str(ROOT / 'test' / 'functional'), env.get('PYTHONPATH', '')])
        command = [sys.executable, '-u', '-m', 'settlement.sandbox', '--resume', str(directory)]
        owned = OwnedProcess(command, directory / 'manager.log', env=env)
        owned.runtime = directory
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if owned.process.poll() is not None:
                    raise RuntimeError('demo exited during startup; inspect its private manager.log')
                fresh = load_config(directory / 'ready.json')
                if (fresh['pid'] == owned.process.pid and owner_identity(directory, fresh) == owned.identity
                        and app_ready(fresh['url'])):
                    owned.stream.close()
                    return status(directory)
                time.sleep(.2)
            raise RuntimeError('startup deadline exceeded; inspect private manager.log')
        except BaseException:
            owned.stop(timeout=10)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument('--runtime', type=Path, help='control this runtime instead of the selected demo')
    parser.add_argument('--timeout', type=float, default=120, help='startup/stop deadline in seconds')
    parser.add_argument('action', choices=('select', 'status', 'start', 'stop'))
    parser.add_argument('directory', type=Path, nargs='?', help='existing runtime for select')
    options = parser.parse_args()
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error('timeout must be finite and positive')
    if options.action == 'select' and options.directory is None:
        parser.error('select requires an existing runtime directory')
    if options.action != 'select' and options.directory is not None:
        parser.error('directory is only accepted by select; use --runtime for an override')
    try:
        if options.action == 'select':
            directory = select_runtime(options.directory, options.registry)
            result = status(directory)
        else:
            directory = options.runtime or selected_runtime(options.registry)
            result = status(directory) if options.action == 'status' else globals()[options.action](directory, options.timeout)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        parser.exit(1, type(error).__name__ + ': ' + str(error) + '\n')


if __name__ == '__main__':
    main()

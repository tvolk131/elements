"""Case authorization and sealed delivery. No recovery scalar or plaintext here.

Guardian approver TLS credentials are a local demo fixture, not independent
institutional custody. A production deployment must place them with institutions.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import re
import secrets
import time

from disclosure import Policy, Request
from guardian_service import statement_from
from recovery import digest
from sealed_delivery import envelope_digest
from .approval import canonical
from .store import Problem, ROLES


class Disclosures:
    def __init__(self, store, audit):
        self.store, self.audit, self.curve = store, audit, audit.curve
        self.db = store.db
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS disclosure_keys(user_id TEXT NOT NULL, public_key TEXT NOT NULL,
            created INTEGER NOT NULL, PRIMARY KEY(user_id,public_key));
          CREATE TABLE IF NOT EXISTS disclosure_cases(id TEXT PRIMARY KEY, data TEXT NOT NULL);
        ''')

    def permission(self, user, permission):
        if permission not in ROLES.get(user['role'], set()):
            raise Problem('this account cannot perform this disclosure action', 403)

    def users(self):
        return [json.loads(row[0]) for row in self.db.execute('SELECT data FROM users ORDER BY id')]

    def recipients(self):
        active = {user['id']: user for user in self.users() if not user.get('disabled')
                  and 'receive_disclosure' in ROLES.get(user['role'], set())}
        return [{'id': user_id, 'name': active[user_id].get('name', user_id), 'public_key': public,
                 'fingerprint': hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16]}
                for user_id, public in self.db.execute('SELECT user_id,public_key FROM disclosure_keys ORDER BY created DESC')
                if user_id in active]

    def register_key(self, user, body):
        self.permission(user, 'receive_disclosure')
        public = body.get('public_key', '')
        try:
            point = bytes.fromhex(public)
            self.curve.parse(point, allow_infinity=False)
        except (ValueError, TypeError):
            raise Problem('enter a valid compressed recipient public key') from None
        if len(point) != 33:
            raise Problem('recipient key must be compressed')
        with self.store.transaction():
            count = self.db.execute('SELECT count(*) FROM disclosure_keys WHERE user_id=?', (user['id'],)).fetchone()[0]
            if count >= 16 and not self.db.execute('SELECT 1 FROM disclosure_keys WHERE user_id=? AND public_key=?', (user['id'], public)).fetchone():
                raise Problem('recipient key retention limit reached', 409)
            self.db.execute('INSERT OR IGNORE INTO disclosure_keys VALUES(?,?,?)', (user['id'], point.hex(), int(time.time())))
            self.store.evidence(user['id'], 'disclosure_recipient_registered', {'public_key': point.hex()})
        return {'registered': True, 'public_key': point.hex()}

    def _source_access(self, user, operation):
        ids = [operation['account_id'], operation.get('to_account_id')]
        return any(self.store.can_view(user, self.store.account(value)) for value in ids if value)

    def targets(self, user, operation_id):
        self.permission(user, 'request_disclosure')
        operation = self.store._operation(operation_id)
        if 'network_disclosures' not in ROLES[user['role']] and not self._source_access(user, operation):
            raise Problem('payment not found', 404)
        txid = operation.get('txid')
        if not txid:
            raise Problem('choose a payment with a confirmed chain transaction', 409)
        decoded = self.audit.node.getrawtransaction(txid, True)
        if not decoded.get('blockhash') or decoded.get('confirmations', 0) < 1:
            raise Problem('payment is not confirmed', 409)
        # A receiving bank may request only its destination output, never the
        # sending customer's change. The source bank sees its own transaction.
        source_allowed = operation['kind'] != 'receipt' and self.store.can_view(user, self.store.account(operation['account_id']))
        receipt_only = operation['kind'] == 'receipt' and 'network_disclosures' not in ROLES[user['role']]
        payment_script = self.audit.node.validateaddress(operation['destination']).get('scriptPubKey')
        destination_script = None
        if not source_allowed and 'network_disclosures' not in ROLES[user['role']]:
            destination_script = payment_script
        result = []
        for output in decoded['vout']:
            if receipt_only and output['n'] != operation.get('output_index'):
                continue
            if not output.get('valuecommitment') or not output.get('assetcommitment'):
                continue
            if not receipt_only and destination_script is not None and output['scriptPubKey']['hex'] != destination_script:
                continue
            result.append({'txid': txid, 'output_index': output['n'], 'label': 'Payment destination' if output['scriptPubKey']['hex'] == payment_script else 'Change or other output'})
        if not source_allowed and 'network_disclosures' not in ROLES[user['role']] and not destination_script and not receipt_only:
            result = []
        return {'operation_id': operation_id, 'outputs': result}

    def create(self, user, body):
        self.permission(user, 'request_disclosure')
        self.store.check_rotation_hold()
        if not isinstance(body.get('reason'), str) or not isinstance(body.get('authority'), str):
            raise Problem('provide a requesting authority and a case reason')
        reason, authority = body['reason'].strip(), body['authority'].strip()
        if not 8 <= len(reason) <= 1000 or not 3 <= len(authority) <= 160:
            raise Problem('provide a requesting authority and a meaningful case reason')
        recipient = next((r for r in self.recipients() if r['id'] == body.get('recipient_id')
                          and r['public_key'] == body.get('recipient_key')), None)
        if recipient is None:
            raise Problem('choose a registered named recipient and public key')
        ttl = body.get('expires_in', 3600)
        if type(ttl) is not int or not 60 <= ttl <= 86400:
            raise Problem('case validity must be between one minute and 24 hours')
        targets = body.get('targets')
        if not isinstance(targets, list) or not 1 <= len(targets) <= 4 or not all(isinstance(t, dict) for t in targets):
            raise Problem('select between one and four outputs')
        operation_id = body.get('operation_id')
        if operation_id:
            allowed = {(o['txid'], o['output_index']) for o in self.targets(user, operation_id)['outputs']}
            if any((t.get('txid'), t.get('output_index')) not in allowed for t in targets):
                raise Problem('an output is outside this bank\'s payment scope', 403)
        elif 'network_disclosures' not in ROLES[user['role']]:
            raise Problem('bank cases must reference one of the bank\'s payments', 403)
        pairs = [(t.get('txid'), t.get('output_index')) for t in targets]
        if any(not isinstance(txid, str) or re.fullmatch('[a-f0-9]{64}', txid) is None
               or type(index) is not int or not 0 <= index <= 65535 for txid, index in pairs) or len(set(pairs)) != len(pairs):
            raise Problem('invalid or duplicate output references')
        now, case_id = int(time.time()), secrets.token_hex(16)
        contexts = [self.audit.disclosure_context(txid, index) for txid, index in pairs]
        configuration = self.audit.current_config()
        if any(c['configuration'] != configuration.binding().hex() for c in contexts):
            raise Problem('membership changed while preparing the case; try again', 409)
        manifest = {'id': case_id, 'requester_id': user['id'], 'bank_tenant': user['tenant'],
                    'recipient': recipient, 'authority': authority, 'reason': reason,
                    'created_at': now, 'expires_at': now + ttl, 'operation_id': operation_id,
                    'targets': [{'txid': c['txid'], 'output_index': c['output_index'],
                                 'approval_block': c.get('approval_block'), 'approval_height': c.get('approval_height'),
                                 'creation_block': c['creation_block'], 'statement': c['statement'],
                                 'packet_hash': digest(b'packet', bytes.fromhex(c['packet'])).hex()} for c in contexts]}
        reference = digest(b'settlement-disclosure-case', canonical(manifest))
        for context in contexts:
            key = configuration.key(context['key_version'])
            policy = Policy(key.committee.binding(), key.committee.threshold, configuration.identities)
            statement = statement_from(context['statement'])
            request = Request(policy.binding(), statement.binding(), digest(b'packet', bytes.fromhex(context['packet'])),
                              reference, bytes.fromhex(recipient['public_key']), now + ttl, 'sealed-v1')
            context['policy'] = {'committee_binding': policy.committee_binding.hex(), 'threshold': policy.threshold,
                                 'approvers': [(member, public.hex()) for member, public in policy.approvers]}
            context['request'] = {'policy_binding': policy.binding().hex(), 'statement_binding': statement.binding().hex(),
                                  'packet_binding': request.packet_binding.hex(), 'case_reference': reference.hex(),
                                  'recipient_key': recipient['public_key'], 'expires_at': request.expires_at, 'delivery': 'sealed-v1'}
            context['request_binding'] = request.binding().hex()
            context['approvals'], context['sealed_partials'] = {}, {}
        case = {'id': case_id, 'manifest': manifest, 'manifest_hash': reference.hex(),
                'configuration': configuration.binding().hex(), 'state': 'awaiting_approval', 'outputs': contexts,
                'threshold': max(len(c['committee']['commitments']) for c in contexts), 'declined': [], 'error': None}
        with self.store.transaction():
            self.db.execute('INSERT INTO disclosure_cases VALUES(?,?)', (case_id, canonical(case).decode()))
            self.store.evidence(user['id'], 'disclosure_requested', {'case_id': case_id, 'manifest_hash': reference.hex()})
        return self.public(user, case)

    def save(self, case):
        self.db.execute('UPDATE disclosure_cases SET data=? WHERE id=?', (canonical(case).decode(), case['id']))

    def load(self, case_id):
        row = self.db.execute('SELECT data FROM disclosure_cases WHERE id=?', (case_id,)).fetchone()
        if not row:
            raise Problem('disclosure case not found', 404)
        case = json.loads(row[0])
        if digest(b'settlement-disclosure-case', canonical(case['manifest'])).hex() != case['manifest_hash']:
            raise Problem('stored disclosure manifest failed its integrity check', 503)
        return case

    def visible(self, user, case):
        manifest = case['manifest']
        return (('review_disclosure' in ROLES[user['role']] and user.get('audit_member') in self.audit.current_config().active_key.committee.members)
                or 'network_disclosures' in ROLES[user['role']]
                or ('request_disclosure' in ROLES[user['role']] and user['tenant'] == manifest['bank_tenant'])
                or ('receive_disclosure' in ROLES[user['role']] and user['id'] == manifest['recipient']['id']))

    def get(self, user, case_id):
        case = self.load(case_id)
        if not self.visible(user, case):
            raise Problem('disclosure case not found', 404)
        return case

    def state(self, case):
        if case['state'] in ('delivered', 'cancelled'):
            return case['state']
        if not any(r['id'] == case['manifest']['recipient']['id'] and r['public_key'] == case['manifest']['recipient']['public_key'] for r in self.recipients()):
            return 'recipient_unavailable'
        if case['manifest']['expires_at'] <= int(time.time()):
            return 'expired'
        if case['configuration'] != self.audit.current_config().binding().hex():
            return 'membership_changed'
        return case['state']

    def public(self, user, case):
        actions, state = [], self.state(case)
        member = str(user.get('audit_member', ''))
        approved = set.intersection(*(set(o['approvals']) for o in case['outputs']))
        if 'review_disclosure' in ROLES[user['role']] and state in ('awaiting_approval', 'ready') and member not in approved:
            if user.get('audit_member') in case['outputs'][0]['committee']['members']:
                actions.extend(['approve', 'decline'])
        if state in ('ready', 'releasing') and (user['id'] in (case['manifest']['requester_id'], case['manifest']['recipient']['id']) or 'network_disclosures' in ROLES[user['role']]):
            actions.append('release')
        if case['state'] in ('awaiting_approval', 'ready') and user['id'] == case['manifest']['requester_id']:
            actions.append('cancel')
        if user['id'] == case['manifest']['recipient']['id'] and any(o['sealed_partials'] for o in case['outputs']):
            actions.append('download')
        requester = self.db.execute('SELECT data FROM users WHERE id=?', (case['manifest']['requester_id'],)).fetchone()
        return {'id': case['id'], **{k: v for k, v in case['manifest'].items() if k != 'targets'},
                # Display only; the signed manifest keeps the account ID.
                'requester_name': json.loads(requester[0]).get('name') if requester else None,
                'manifest_hash': case['manifest_hash'], 'state': state, 'threshold': case['threshold'],
                'approved_members': sorted(int(m) for m in approved), 'declined_members': case['declined'],
                'guardian_count': len(case['outputs'][0]['committee']['members']),
                'outputs': [{k: o[k] for k in ('txid', 'output_index', 'creation_height', 'key_version')} | {'released_partials': len(o['sealed_partials'])} for o in case['outputs']],
                'error': case['error'], 'allowed_actions': actions}

    def overview(self, user):
        if not ROLES[user['role']] & {'request_disclosure', 'review_disclosure', 'receive_disclosure'}:
            raise Problem('disclosure workspace is not available to this account', 403)
        cases = [json.loads(row[0]) for row in self.db.execute('SELECT data FROM disclosure_cases ORDER BY rowid DESC')]
        return {'cases': [self.public(user, case) for case in cases if self.visible(user, case)],
                'recipients': self.recipients(), 'my_keys': [r for r in self.recipients() if r['id'] == user['id']],
                'members': list(self.audit.current_config().active_key.committee.members)}

    def approve(self, user, case_id, decline=False):
        self.permission(user, 'review_disclosure')
        case = self.get(user, case_id)
        if self.state(case) not in ('awaiting_approval', 'ready'):
            raise Problem('case is expired, cancelled, released or uses a previous membership', 409)
        self.store.check_rotation_hold()
        member = user.get('audit_member')
        if member not in case['outputs'][0]['committee']['members']:
            raise Problem('this guardian is not in the case committee', 403)
        if decline:
            if member not in case['declined']:
                case['declined'].append(member)
        else:
            for output in case['outputs']:
                result = self.audit.cluster.guardians[member].request('approve', credentials=self.audit.cluster.approvers[member],
                        key_version=output['key_version'], policy=output['policy'], request=output['request'])
                identities = dict(output['identities'])
                if result['member'] != member or not self.curve.verify_signature(bytes.fromhex(identities[member]),
                        bytes.fromhex(output['request_binding']), bytes.fromhex(result['signature'])):
                    raise Problem('guardian returned an invalid approval', 503)
                output['approvals'][str(member)] = result
            case['declined'] = [m for m in case['declined'] if m != member]
        if all(len(o['approvals']) >= len(o['committee']['commitments']) for o in case['outputs']):
            case['state'] = 'ready'
        with self.store.transaction():
            self.save(case)
            self.store.evidence(user['id'], 'disclosure_declined' if decline else 'disclosure_approved', {'case_id': case_id, 'member': member, 'manifest_hash': case['manifest_hash']})
        return self.public(user, case)

    def release(self, user, case_id):
        case = self.get(user, case_id)
        if 'release' not in self.public(user, case)['allowed_actions']:
            raise Problem('case needs its guardian quorum before encrypted release', 403)
        self.store.check_rotation_hold()
        # No partials or recovered openings are returned by this relay endpoint.
        case['state'], case['error'] = 'releasing', None
        with self.store.transaction():
            self.save(case)
        for output in case['outputs']:
            if self.audit.node.getblockhash(output['creation_height']) != output['creation_block']:
                raise Problem('the approved output is no longer on the active chain', 409)
            approvals = [{'member': int(m), 'signature': a['signature']} for m, a in output['approvals'].items()]
            payload = {k: output[k] for k in ('key_version', 'policy', 'request', 'statement', 'packet')}
            payload['approvals'] = approvals
            def obtain(member):
                return member, self.audit.cluster.guardians[member].request('disclose-sealed', **payload)
            missing = [int(m) for m in output['approvals'] if m not in output['sealed_partials']]
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(obtain, member) for member in missing]
                for future in as_completed(futures):
                    try:
                        member, envelope = future.result()
                        if (envelope['member'] != member or envelope['request_binding'] != output['request_binding']
                                or envelope['recipient_key'] != case['manifest']['recipient']['public_key']
                                or not self.curve.verify_signature(bytes.fromhex(dict(output['identities'])[member]), envelope_digest(envelope), bytes.fromhex(envelope['signature']))):
                            raise ValueError('invalid sealed guardian response')
                        output['sealed_partials'][str(member)] = envelope
                        with self.store.transaction():
                            self.save(case)
                    except Exception:
                        case['error'] = 'Some guardian releases failed. Stored encrypted contributions are retained; retry before expiry.'
            if self.state(case) in ('expired', 'membership_changed'):
                break
        if all(len(o['sealed_partials']) >= len(o['committee']['commitments']) for o in case['outputs']):
            case['state'], case['error'] = 'delivered', None
        with self.store.transaction():
            self.save(case)
            self.store.evidence(user['id'], 'disclosure_encrypted_release', {'case_id': case_id, 'manifest_hash': case['manifest_hash'], 'state': self.state(case),
                                      'released': [len(o['sealed_partials']) for o in case['outputs']]})
        return self.public(user, case)

    def cancel(self, user, case_id):
        case = self.get(user, case_id)
        if 'cancel' not in self.public(user, case)['allowed_actions']:
            raise Problem('only an unreleased case can be cancelled by its requester', 409)
        case['state'] = 'cancelled'
        with self.store.transaction():
            self.save(case)
            self.store.evidence(user['id'], 'disclosure_cancelled', {'case_id': case_id})
        return self.public(user, case)

    def bundle(self, user, case_id):
        case = self.get(user, case_id)
        if 'download' not in self.public(user, case)['allowed_actions']:
            raise Problem('encrypted packages are available only to the named recipient', 403)
        return {'format': 'concord-sealed-disclosure-v1', 'manifest': case['manifest'], 'manifest_hash': case['manifest_hash'],
                'outputs': case['outputs'], 'state': self.state(case),
                'verification': 'Recipient must verify guardian signatures, partial proofs and commitment openings. Creation policy and chain inclusion require a trusted chain observer.'}

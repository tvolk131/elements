"""Run the complete local settlement sandbox. No real bank connection.

Usage from repository root:
 PYTHONPATH=contrib/threshold-audit:test/functional python3 -m settlement.sandbox
Without --directory, runtime secrets and chain data live in a new private
directory under ~/.local/state/elements-audit/runtimes (XDG_STATE_HOME).
"""

import argparse
from dataclasses import replace
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import tempfile
import threading
import time

from curve import Curve, random_scalar
from guardian_client import GuardianCluster
from guardian_service import atomic_write
from governance import AuditConfig
from native_governance import policy_binding, prepared_to_bytes
from test_framework import messages
from .approval import ApprovalVerifier, ApprovalPolicies
from .elements_adapter import ElementsAdapter, RPC
from .server import create_server
from .store import Settlement
from .federation_audit import AuditRotation
from .federation_blocks import BlockFederation, BOOTSTRAP_SCRIPT
from .federation import FederationRotation
from .treasury_rotation import public_policy
from .authorization import policy_bytes, registration_digest
from .runtime import OwnedProcesses, load_config, read_ready_line, save_config, state_directory
from test_framework.script import CScript, OP_CHECKMULTISIG


ROOT = Path(__file__).resolve().parents[3]
# A customer wallet at another member bank on the network. The app does not
# run it, but its bank has registered its addresses, so tests can receive
# payments from outside the app. The sandbox's one simulated bank key stands
# in for that bank's.
OTHER_MEMBER_BANK_WALLET = 'other-member-bank'
# One federation: the operators sign blocks, authorize transactions, co-sign
# issuance and hold the disclosure key, all at the same threshold.
OPERATORS, QUORUM = 7, 5


def private_json(path, value):
    if isinstance(value, dict):
        save_config(path, value)
    else:
        atomic_write(path, value)


def display_name(username):
    """Operators sign in as institution-N; people know them as Operator N."""
    if username.startswith('institution-'):
        return 'Operator ' + username.rsplit('-', 1)[1]
    return username.replace('-', ' ').title()


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_rpc(rpc, process):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('Elements exited; inspect the private runtime daemon.log')
        try:
            return rpc.getblockchaininfo()
        except (OSError, RuntimeError, ValueError):
            time.sleep(.1)
    raise RuntimeError('Elements RPC readiness deadline exceeded')


def mine(node, count=1, proposal=None):
    for _ in range(count):
        raw = node.getnewblockhex() if proposal is None else node.getnewblockhex(0, proposal)
        result = node.submitblock(raw)
        if result is not None:
            raise RuntimeError('sandbox block rejected: ' + str(result))


def bootstrap_assets(node, sponsor, cluster, genesis_config, curve):
    assets = {}
    for currency in ('EUR', 'USD'):
        # The initial supply is zero. Only one indivisible authority balance is
        # created; all its units are transferred to the federation after the
        # asset and authority IDs are registered by DynaFed.
        address = sponsor.getnewaddress('', 'bech32')
        funding = sponsor.sendtoaddress(address, 2)
        mine(node)
        coin = next(coin for coin in sponsor.listunspent(1) if coin['txid'] == funding and coin['address'] == address)
        raw = sponsor.createrawtransaction([{'txid': coin['txid'], 'vout': coin['vout']}], [{address: Decimal('1.99')}])
        transaction = sponsor.fundrawtransaction(raw, {'fee_rate': 2, 'changeAddress': sponsor.getrawchangeaddress('bech32')})['hex']
        issuance = sponsor.rawissueasset(transaction, [{'token_amount': 1, 'token_address': sponsor.getnewaddress('', 'bech32'),
                                                      'blind': False, 'contract_hash': hashlib.sha256(('Test' + currency).encode()).hexdigest()}])[0]
        signed = sponsor.signrawtransactionwithwallet(issuance['hex'])
        if not signed['complete']:
            raise RuntimeError('initial asset registration transaction could not be signed')
        node.sendrawtransaction(signed['hex'], 0)
        mine(node)
        assets[currency] = {'asset_id': issuance['asset'], 'token_id': issuance['token'], 'entropy': issuance['entropy'],
                            'decimals': 2, 'reserve_model': 'simulated segregated custodian account',
                            'redemption_obligor': 'undecided'}
    while node.getblockcount() % 10:
        mine(node)
    info = node.getblockchaininfo()
    registry = tuple(sorted({bytes.fromhex(value)[::-1] for value in info['audit_assets']}
                            | {bytes.fromhex(asset[field])[::-1] for asset in assets.values() for field in ('asset_id', 'token_id')}))
    program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
    binding = policy_binding(program, 108, program, b'\x51', [], audit_assets=registry, audit_assets_version=1)
    current = AuditConfig.from_bytes(bytes.fromhex(info['audit_config']), curve)
    config = replace(current, generation=current.generation + 1, signer_policy=binding)
    activation = node.getblockcount() + 10
    chain_id = bytes.fromhex(node.getblockhash(0))[::-1]
    prepared = cluster.prepare(chain_id, config, {}, previous=current, activation_height=activation)
    proposal = {'signblockscript': program.hex(), 'max_block_witness': 108, 'fedpegscript': '51', 'extension_space': [],
                'audit_pubkey': config.active_key.public_key.hex(), 'audit_version': config.active_version,
                'audit_config': config.to_bytes().hex(), 'audit_prepared': prepared_to_bytes(prepared).hex(),
                'audit_assets': [asset[::-1].hex() for asset in registry], 'audit_assets_version': 1}
    while node.getblockcount() < activation - 1:
        mine(node, proposal=proposal)
    mine(node)
    cluster.activate(chain_id, prepared)
    if set(node.getblockchaininfo()['audit_assets']) != {asset[::-1].hex() for asset in registry}:
        raise RuntimeError('on-chain currency registry did not activate')
    return assets


class Sandbox:
    def __init__(self, directory, daemon, library):
        self.directory, self.daemon, self.library = Path(directory), str(daemon), str(library)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.processes = OwnedProcesses(self.directory)
        self.children = self.processes.children
        self.cluster, self.server, self.node = None, None, None
        self.stop = threading.Event()
        self.mining_lock = threading.RLock()
        self.institution_processes = {}
        self.institution_endpoints = {}
        self.institution_lock = threading.Lock()
        self.closed = False
        self.mesh = None

    def start(self, port=0):
        messages.THRESHOLD_AUDIT = True
        port = port or free_port()
        curve = Curve(self.library)
        program = b'\x00\x20' + hashlib.sha256(b'\x51').digest()
        # Operator N holds disclosure key piece N (a separate key and service).
        self.cluster = GuardianCluster(self.directory / 'audit-guardians', tuple(range(1, OPERATORS + 1)), self.library,
                                       curve, curve.mul(random_scalar()))
        genesis_config, plans = self.cluster.bootstrap_genesis(tuple(range(1, OPERATORS + 1)), QUORUM,
                                      policy_binding(program, 108, program, b'\x51', [b'']))
        datadir = self.directory / 'node'
        datadir.mkdir(mode=0o700)
        rpc_port, rpc_secret = free_port(), secrets.token_hex(24)
        rpc_url = f'http://sandbox:{rpc_secret}@127.0.0.1:{rpc_port}'
        args = [self.daemon, '-datadir=' + str(datadir), '-chain=auditregtest', '-server=1', '-listen=0',
                '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-rpcport=' + str(rpc_port), '-rpcuser=sandbox',
                '-rpcpassword=' + rpc_secret, '-con_threshold_audit=1', '-evbparams=dynafed:-1:::',
                '-con_audit_config=' + genesis_config.to_bytes().hex(), '-con_start_p2wsh_script=1',
                '-con_max_block_sig_size=108', '-pak=', '-enforce_pak=0', '-initialfreecoins=2100000000000000',
                '-anyonecanspendaremine=1', '-con_blocksubsidy=0', '-con_connect_genesis_outputs=1',
                '-dynamic_epoch_length=10', '-txindex=1', '-blindedaddresses=1', '-creatediscountct=0',
                '-acceptdiscountct=0', '-connect=0', '-listenonion=0', '-dnsseed=0', '-fixedseeds=0',
                '-deprecatedrpc=create_bdb', '-validatepegin=0', '-limitancestorsize=1000', '-limitdescendantsize=1000']
        save_config(self.directory / 'launcher.json', {'daemon_args': args})
        self.process = self.processes.spawn(args, self.directory / 'daemon.log')
        node = self.node = RPC(rpc_url)
        wait_rpc(node, self.process)
        node.createwallet('sponsor', False, False, '', False, False)
        sponsor_url = rpc_url + '/wallet/sponsor'
        sponsor = RPC(sponsor_url)
        sponsor.rescanblockchain(0)
        chain_id = bytes.fromhex(node.getblockhash(0))[::-1]
        prepared = self.cluster.prepare(chain_id, genesis_config, plans)
        self.cluster.activate(chain_id, prepared)
        node.generatetoaddress(101, sponsor.getnewaddress('', 'bech32'))
        print('Elements ready; registering the UNITED EUR and UNITED USD test tokens through DynaFed.', flush=True)
        assets = bootstrap_assets(node, sponsor, self.cluster, genesis_config, curve)
        institutions = {}
        public_keys, spending_public, secrets_by_guardian, block_public_keys = {}, [], {}, {}
        for number in range(1, OPERATORS + 1):
            guardian = f'institution-{number}'
            spending, approval, block_secret = random_scalar(), random_scalar(), random_scalar()
            public_keys[guardian] = curve.mul(approval)[1:].hex()
            spending_public.append(curve.mul(spending).hex())
            block_public_keys[guardian] = curve.mul(block_secret).hex()
            secrets_by_guardian[guardian] = (spending, approval, block_secret)
        block_witness = bytes(CScript([QUORUM, *[bytes.fromhex(key) for key in block_public_keys.values()], OPERATORS, OP_CHECKMULTISIG]))
        block_script = (b'\x00\x20' + hashlib.sha256(block_witness).digest()).hex()
        multisig = sponsor.addmultisigaddress(QUORUM, spending_public, 'federation-treasury', 'bech32')
        treasury = sponsor.getaddressinfo(multisig['address'])
        base_address = treasury.get('unconfidential', multisig['address'])
        sponsor.importaddress(base_address, 'federation-treasury', False)
        blinding_secret = random_scalar()
        treasury_address = sponsor.createblindedaddress(base_address, curve.mul(blinding_secret).hex())
        sponsor.importblindingkey(treasury_address, f'{blinding_secret:064x}')
        treasury_script = sponsor.validateaddress(treasury_address)['scriptPubKey']
        witness_script = multisig.get('redeemScript') or treasury.get('hex')
        if not witness_script:
            raise RuntimeError('federation witness script unavailable')
        for asset in assets.values():
            sponsor.sendtoaddress(treasury_address, 1, '', '', False, False, 1, 'UNSET', False, asset['token_id'])
            mine(node)
        bank_secret = random_scalar()
        bank_public = curve.mul(bank_secret)[1:].hex()
        private_json(self.directory / 'simulated-bank.json', {'signing_secret': f'{bank_secret:064x}'})
        institution_passphrases = {}
        for guardian, (spending, approval, block_secret) in secrets_by_guardian.items():
            directory = self.directory / guardian
            directory.mkdir(mode=0o700)
            token = secrets.token_hex(32)
            institution_passphrases[guardian] = secrets.token_urlsafe(24)
            config = {'guardian_id': guardian, 'spending_secret': f'{spending:064x}', 'approval_secret': f'{approval:064x}',
                      'approval_public_keys': public_keys, 'threshold': QUORUM, 'genesis_hash': node.getblockhash(0),
                      'assets': assets, 'treasury_address': treasury_address,
                      'treasury_script': treasury_script, 'witness_script': witness_script,
                      'bank_public_key': bank_public, 'policy_asset': node.getblockchaininfo()['audit_assets'][0],
                      'token': token, 'database': str(directory / 'signing.sqlite'), 'library': self.library,
                      'rpc_url': rpc_url, 'approval_passphrase': institution_passphrases[guardian],
                      'guardian_order': list(public_keys), 'policy_version': 'sandbox-v1',
                      'block_secret': f'{block_secret:064x}', 'block_public_keys': block_public_keys,
                      'block_witness_script': block_witness.hex(), 'block_signing_script': block_script,
                      'coordinator_origins': [f'http://127.0.0.1:{port}', f'http://localhost:{port}']}
            # Policy asset is independently identified by the genesis network,
            # never by sorted registry index after EUR/USD were appended.
            config['policy_asset'] = next(value for value in node.getblockchaininfo()['audit_assets']
                if value not in {asset[field] for asset in assets.values() for field in ('asset_id', 'token_id')})
            path = directory / 'service.json'
            private_json(path, config)
            institutions[guardian] = self._launch_institution(guardian, port)
        del secrets_by_guardian
        wallets, addresses, accounts = {}, {}, []
        for account_id, tenant, name in [('acme-main', 'acme', 'Acme · Operating'),
                                          ('acme-treasury', 'acme', 'Acme · Treasury'),
                                          ('globex-main', 'globex', 'Globex · Operating')]:
            node.createwallet(account_id, False, False, '', False, False)
            wallet_url = rpc_url + '/wallet/' + account_id
            wallet = RPC(wallet_url)
            wallets[account_id], addresses[account_id] = wallet_url, wallet.getnewaddress('', 'blech32')
            sponsor.sendtoaddress(wallet.getnewaddress('', 'bech32'), 1)
            accounts.append({'id': account_id, 'name': name, 'tenant': tenant, 'bank_tenant': 'bank',
                'addresses': {'EUR': addresses[account_id], 'USD': addresses[account_id]},
                'bank_account_ref': 'SIMULATED-' + account_id,
                'beneficiaries': [{'id': account_id + '-' + currency, 'name': name + ' · ' + currency + ' bank account',
                                  'currency': currency, 'bank_account_ref': 'SIMULATED-' + currency + '-' + account_id}
                                 for currency in ('EUR', 'USD')]})
        mine(node)
        adapter_config = {'rpc_url': rpc_url, 'sponsor_rpc_url': sponsor_url, 'wallets': wallets, 'addresses': addresses,
                          'library': self.library, 'assets': assets, 'institutions': institutions,
                          'treasury_address': treasury_address, 'treasury_script': treasury_script,
                          'witness_script': witness_script, 'guardian_order': list(institutions), 'threshold': QUORUM,
                          'approval_public_keys': public_keys,
                          'policy_version': 'sandbox-v1', 'block_public_keys': block_public_keys,
                          'block_witness_script': block_witness.hex(), 'block_signing_script': block_script,
                          'audit_pool_members': list(range(1, OPERATORS + 1)),
                          # Which operator holds each disclosure key piece.
                          'audit_operators': {str(n): f'institution-{n}' for n in range(1, OPERATORS + 1)},
                          'database': str(self.directory / 'prepared.sqlite')}
        users, credentials = [], []
        roles = [('bank-admin', 'bankadmin', 'bank'), ('bank-maker', 'bankmaker', 'bank'),
                 ('bank-approver', 'bankapprover', 'bank'), ('acme-maker', 'corporatemaker', 'acme'),
                 ('acme-approver', 'corporateapprover', 'acme'), ('globex-maker', 'corporatemaker', 'globex'),
                 ('auditor', 'auditor', 'bank')]
        roles += [(guardian, 'institutionguardian', 'bank') for guardian in institutions]
        for username, role, tenant in roles:
            password = secrets.token_urlsafe(18)
            users.append({'id': username, 'username': username, 'name': display_name(username),
                          'password': password, 'role': role, 'tenant': tenant,
                          **({'institution_id': username, 'audit_member': int(username.rsplit('-', 1)[1])}
                             if role == 'institutionguardian' else {})})
            credentials.append({'username': username, 'password': password, 'role': role,
                                **({'institution_approval_passphrase': institution_passphrases[username]} if role == 'institutionguardian' else {})})
        config = {'accounts': accounts, 'users': users, 'min_confirmations': 1,
                  'institution_approval_urls': {guardian: service['url'] for guardian, service in institutions.items()}}
        private_json(self.directory / 'credentials.json', credentials)
        save_config(self.directory / 'adapter.json', adapter_config)
        # Backend config has no federation spending or approval private keys.
        save_config(self.directory / 'web.json', config)
        return self._serve(adapter_config, config, bank_secret, port)

    def _serve(self, adapter_config, config, bank_secret, port):
        curve = Curve(self.library)
        adapter = self.adapter = ElementsAdapter(adapter_config)
        # The simulated bank vouches only for addresses in wallets it runs: its
        # customers' and the network's own. A real bank would hold this key
        # itself, outside the coordinator.
        genesis = self.node.getblockhash(0)
        other_bank = self._wallet(adapter_config['rpc_url'], OTHER_MEMBER_BANK_WALLET)
        def registrar(script):
            address = self.node.decodescript(script.hex()).get('address')
            if address is None:
                return None
            for wallet in (adapter.sponsor, *adapter.wallets.values(), other_bank):
                info = wallet.getaddressinfo(address)
                if info.get('ismine') or info.get('iswatchonly'):
                    return curve.sign(bank_secret, registration_digest(genesis, script))
            return None
        adapter.registrar = registrar
        public_keys = adapter_config.get('approval_public_keys')
        if public_keys is None:
            # Backward-compatible fixture metadata upgrade uses a public
            # endpoint, never institution spending/approval private files.
            import urllib.request
            service = next(iter(adapter_config['institutions'].values()))
            with urllib.request.urlopen(service['url'] + 'info', timeout=10) as response:
                public_keys = json.load(response)['approval_public_keys']
            adapter_config['approval_public_keys'] = public_keys
            save_config(self.directory / 'adapter.json', adapter_config)
        node = self.node
        history = [ApprovalVerifier(curve, value['public_keys'], value['threshold'], version)
                   for version, value in adapter_config.get('historical_approval_policies', {}).items()]
        verifier = ApprovalPolicies(ApprovalVerifier(curve, public_keys, adapter_config['threshold'], adapter_config.get('policy_version', 'sandbox-v1')), history)
        self.observer = None
        if adapter_config.get('independent_node'):
            from .observer import Observer
            try:
                self.observer = Observer(self.directory, self.processes, free_port).start(
                    node, load_config(self.directory / 'launcher.json')['daemon_args'])
            except Exception as error:
                # The demo runs without it; the ledger page says it is unavailable.
                print('independent node unavailable:', str(error)[:300], flush=True)
        self.blocks = BlockFederation(node, curve, directory=self.directory / 'blocks')
        for policy in adapter_config.get('federation_manifests', []):
            self.blocks.register(policy)
        self.blocks.register(dict(public_policy(adapter_config), institutions=adapter_config['institutions']))
        self.audit = AuditRotation(self.cluster, node, self.directory / 'audit-transitions')
        current_script = node.getblock(node.getbestblockhash())['dynamic_parameters']['current']['signblockscript']
        if current_script == BOOTSTRAP_SCRIPT.hex():
            if (self.directory / 'audit-transitions' / 'install-a.json').exists():
                record = self.audit.load('install-a')
            else:
                self.blocks.align()
                # From this activation on the institutions sign every block
                # and must authorize every transaction.
                record = self.audit.prepare_policy(adapter_config['block_signing_script'], rotation_id='install-a',
                    tx_authorization=policy_bytes(public_keys, adapter_config['guardian_order'], adapter_config['threshold']).hex())
            while node.getblockcount() < record['activation_height'] - 1:
                self.blocks.mine(proposal=self.audit.proposal(record))
            self.blocks.mine()
            self.audit.activate(record)
        elif (self.directory / 'audit-transitions' / 'install-a.json').exists():
            record = self.audit.load('install-a')
            if record['phase'] != 'activated' and current_script == record['signblockscript']:
                self.audit.activate(record)
        self.blocks.allow_bootstrap = False
        self.store = Settlement(self.directory / 'settlement.sqlite', adapter, verifier,
                       config=config, approval_signer=None,
                       bank_signing_secret=bank_secret)
        self.store.federation = FederationRotation(self, self.store)
        self.store.demo_runtime = self
        from .ledger import LedgerView
        self.store.ledger_view = LedgerView(adapter)
        self.store.observer = self.observer
        from .capability_demo import enroll
        enroll(self, config, adapter_config)
        self.blocks.exclude = lambda block: self.store.freezes.excluded(block) if self.store.freezes else []
        if config.get('demo_sign_in'):
            from .theft_drill import TheftDrill
            self.store.theft_drill = TheftDrill(self.store, self)
        self.server = create_server(self.store, port=port)
        self.server.start_worker()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        url = f'http://127.0.0.1:{self.server.server_port}/'
        mesh_path = self.directory / 'mesh.json'
        if mesh_path.exists():
            from .mesh import MeshGateway
            self.mesh = MeshGateway(load_config(mesh_path), url,
                                    lambda: self.store.config.get('institution_approval_urls', {})).start()
        def miner():
            while not self.stop.wait(3):
                try:
                    with self.mining_lock:
                        if not self.store.federation.held:
                            self.blocks.mine()
                except Exception as error:
                    # A missing signer is recoverable. The block helper keeps
                    # the exact candidate for retry and cannot equivocate.
                    self.mining_error = str(error)[:300]
        self.miner = threading.Thread(target=miner, daemon=True)
        self.miner.start()
        save_config(self.directory / 'ready.json', {'url': url, 'pid': os.getpid(), 'genesis_hash': node.getblockhash(0),
                                                   'credentials_file': str(self.directory / 'credentials.json'),
                                                   **({'mesh': self.mesh.urls()} if self.mesh else {})})
        print(json.dumps({'url': url, 'credentials_file': str(self.directory / 'credentials.json'),
                          'runtime': str(self.directory), 'bank': 'SIMULATED', 'currencies': ['UNITED EUR', 'UNITED USD']}), flush=True)
        return self

    def resume(self, port=0):
        """Reload this fixture's existing chain, keys, users and durable outbox."""
        messages.THRESHOLD_AUDIT = True
        ready = load_config(self.directory / 'ready.json')
        from urllib.parse import urlsplit
        port = port or urlsplit(ready['url']).port
        adapter_config = load_config(self.directory / 'adapter.json')
        self.library = adapter_config['library']
        config = load_config(self.directory / 'web.json')
        rotation_path = self.directory / 'federation-rotation.json'
        rotation_state = json.loads(rotation_path.read_text()) if rotation_path.exists() else None
        pool = adapter_config.get('audit_pool_members')
        if rotation_state and rotation_state['stage'] != 'complete':
            # Reopen only this handover's rosters. Earlier retired identities
            # retain files for evidence, but must not be resurrected on C's start.
            audit_record = rotation_state.get('audit')
            audit_path = self.directory / 'audit-transitions' / (rotation_state['id'] + '.json')
            if audit_record is None and audit_path.exists():
                audit_record = json.loads(audit_path.read_text())
            if audit_record:
                enrolled = {int(path.stem.split('-')[-1]) for path in (self.directory / 'audit-guardians').glob('guardian-*.json')
                            if path.stem.split('-')[-1].isdigit()}
                outgoing = set(audit_record['outgoing_members'])
                if not outgoing <= enrolled:
                    raise ValueError('outgoing audit identity is missing; refusing replacement')
                incoming = set(audit_record.get('target_members') or audit_record.get('incoming_members') or [])
                pool = sorted(outgoing | (incoming & enrolled))
        self.cluster = GuardianCluster.resume(self.directory / 'audit-guardians', Curve(self.library), members=pool)
        args = load_config(self.directory / 'launcher.json')['daemon_args']
        self.process = self.processes.spawn(args, self.directory / 'daemon.log')
        self.node = RPC(adapter_config['rpc_url'])
        wait_rpc(self.node, self.process)
        loaded = set(self.node.listwallets())
        for wallet in ['sponsor', *adapter_config['wallets']]:
            if wallet not in loaded:
                self.node.loadwallet(wallet)
        if self.node.getblockhash(0) != ready['genesis_hash']:
            raise RuntimeError('persisted sandbox genesis hash changed')
        services = {}
        service_configs = {guardian: load_config(self.directory / guardian / 'service.json') for guardian in adapter_config['institutions']}
        native_script = self.node.getblock(self.node.getbestblockhash())['dynamic_parameters']['current']['signblockscript']
        for service in service_configs.values():
            # Older fixtures stored this public address only in adapter.json.
            service.setdefault('treasury_address', adapter_config['treasury_address'])
            if 'block_secret' not in service:
                if native_script != BOOTSTRAP_SCRIPT.hex():
                    raise ValueError('active operator block identity is missing; refusing key replacement')
                service['block_secret'] = f'{random_scalar():064x}'
        block_keys = {guardian: self.cluster.curve.mul(int(service['block_secret'], 16)).hex() for guardian, service in service_configs.items()}
        witness = bytes(CScript([adapter_config['threshold'], *[bytes.fromhex(block_keys[guardian]) for guardian in adapter_config['guardian_order']], len(block_keys), OP_CHECKMULTISIG]))
        derived_script = (b'\x00\x20' + hashlib.sha256(witness).digest()).hex()
        if adapter_config.get('block_signing_script', derived_script) != derived_script:
            raise ValueError('persisted block keys do not match the configured public policy')
        adapter_config.update(block_public_keys=block_keys, block_witness_script=witness.hex(),
                              block_signing_script=derived_script,
                              policy_version=adapter_config.get('policy_version', 'sandbox-v1'))
        for guardian in adapter_config['institutions']:
            path = self.directory / guardian / 'service.json'
            service = service_configs[guardian]
            service.update({key: adapter_config[key] for key in ('block_public_keys', 'block_witness_script', 'block_signing_script', 'guardian_order', 'policy_version')})
            service['coordinator_origins'] = [f'http://127.0.0.1:{port}', f'http://localhost:{port}']
            private_json(path, service)
            services[guardian] = self._launch_institution(guardian, port)
        adapter_config['institutions'] = services
        if rotation_state and rotation_state['stage'] != 'complete' and rotation_state.get('target'):
            target = rotation_state['target']
            for guardian in target['policy']['guardian_order']:
                if guardian in services:
                    target['institutions'][guardian] = services[guardian]
                else:
                    target['institutions'][guardian] = self._launch_institution(guardian, port)
            self.blocks_pending_target = target
            atomic_write(rotation_path, rotation_state)
            adapter_config.setdefault('federation_manifests', []).append(dict(target['policy'], institutions=target['institutions']))
        config['institution_approval_urls'] = {guardian: service['url'] for guardian, service in services.items()}
        save_config(self.directory / 'adapter.json', adapter_config)
        save_config(self.directory / 'web.json', config)
        secret = int(load_config(self.directory / 'simulated-bank.json')['signing_secret'], 16)
        return self._serve(adapter_config, config, secret, port)

    def persist_adapter(self):
        save_config(self.directory / 'adapter.json', self.adapter.config)

    def _launch_institution(self, guardian, port, service_port=None):
        process = self.institution_processes.get(guardian)
        if process is not None and process.poll() is None:
            return self.institution_endpoints[guardian]
        path = self.directory / guardian / 'service.json'
        service = load_config(path)
        service['coordinator_origins'] = [f'http://127.0.0.1:{port}', f'http://localhost:{port}']
        save_config(path, service)
        process = self.processes.spawn([sys.executable, '-u', '-m', 'settlement.treasury', str(path),
                                        *([str(service_port)] if service_port else [])],
                                       path.parent / 'stderr.log', readiness=True)
        self.institution_processes[guardian] = process
        try:
            endpoint = read_ready_line(process)
            from urllib.parse import urlsplit
            parsed = urlsplit(endpoint['url'])
            if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port:
                raise ValueError('operator readiness is not a loopback endpoint')
        except BaseException:
            self.processes.stop(process)
            raise
        result = {'url': endpoint['url'], 'token': service['token']}
        self.institution_endpoints[guardian] = result
        return result

    def create_incoming(self, epoch):
        """Create/reload independent fixture identities; keep keys out of web config."""
        label = chr(96 + epoch)
        ids = [f'institution-{label}-{number}' for number in range(1, OPERATORS + 1)]
        curve = self.cluster.curve
        source = public_policy(self.adapter.config)
        history = dict(self.adapter.config.get('historical_approval_policies', {}))
        previous = history.get(source['policy_version'])
        if previous and (previous.get('public_keys', previous.get('approval_public_keys')) != source['approval_public_keys']
                         or previous['threshold'] != source['threshold']):
            raise ValueError('historical operator policy cannot be replaced')
        if previous and any(previous[key] != source[key] for key in (
                'treasury_script', 'witness_script', 'treasury_address', 'guardian_order',
                'block_signing_script', 'block_witness_script', 'block_public_keys') if key in previous):
            raise ValueError('historical operator scripts or roster cannot be replaced')
        preserved = dict(source)
        preserved.update(previous or {})
        preserved['public_keys'] = source['approval_public_keys']
        history[source['policy_version']] = preserved
        configs = {}
        credentials_path = self.directory / 'credentials.json'
        credentials = json.loads(credentials_path.read_text())
        for guardian in ids:
            directory = self.directory / guardian; directory.mkdir(mode=0o700, exist_ok=True)
            path = directory / 'service.json'
            if path.exists():
                config = load_config(path)
            else:
                config = {'guardian_id': guardian, 'spending_secret': f'{random_scalar():064x}',
                          'approval_secret': f'{random_scalar():064x}', 'block_secret': f'{random_scalar():064x}',
                          'approval_passphrase': secrets.token_urlsafe(24), 'token': secrets.token_hex(32),
                          'database': str(directory / 'signing.sqlite'), 'library': self.library,
                          'rpc_url': self.adapter.config['rpc_url'], 'genesis_hash': self.node.getblockhash(0)}
                private_json(path, config)
            configs[guardian] = config
            if not any(item['username'] == guardian for item in credentials):
                credentials.append({'username': guardian, 'password': secrets.token_urlsafe(18), 'role': 'institutionguardian',
                                    'institution_approval_passphrase': config['approval_passphrase']})
        private_json(credentials_path, credentials)
        public_keys = {guardian: curve.mul(int(config['approval_secret'], 16))[1:].hex() for guardian, config in configs.items()}
        block_keys = {guardian: curve.mul(int(config['block_secret'], 16)).hex() for guardian, config in configs.items()}
        spend_keys = [curve.mul(int(configs[guardian]['spending_secret'], 16)).hex() for guardian in ids]
        multisig = self.adapter.sponsor.addmultisigaddress(QUORUM, spend_keys, f'federation-{label}', 'bech32')
        address = self.adapter.sponsor.getaddressinfo(multisig['address'])
        base = address.get('unconfidential', multisig['address'])
        self.adapter.sponsor.importaddress(base, f'federation-{label}', False)
        # Address blinding is view authority, separate from spending quorum.
        view_path = self.directory / f'federation-{label}-view.json'
        if view_path.exists():
            view = int(load_config(view_path)['secret'], 16)
        else:
            view = random_scalar(); private_json(view_path, {'secret': f'{view:064x}'})
        blinded = self.adapter.sponsor.createblindedaddress(base, curve.mul(view).hex())
        self.adapter.sponsor.importblindingkey(blinded, f'{view:064x}')
        block_witness = bytes(CScript([QUORUM, *[bytes.fromhex(block_keys[guardian]) for guardian in ids], OPERATORS, OP_CHECKMULTISIG]))
        policy = {'policy_version': f'sandbox-v{epoch}', 'approval_public_keys': public_keys, 'guardian_order': ids, 'threshold': QUORUM,
                  'treasury_script': self.adapter.sponsor.validateaddress(blinded)['scriptPubKey'],
                  'witness_script': multisig.get('redeemScript') or address['hex'], 'treasury_address': blinded,
                  'block_signing_script': (b'\x00\x20' + hashlib.sha256(block_witness).digest()).hex(),
                  'block_witness_script': block_witness.hex(), 'block_public_keys': block_keys}
        policy_asset = next(asset for asset in self.node.getblockchaininfo()['audit_assets']
                            if asset not in {value[field] for value in self.adapter.config['assets'].values() for field in ('asset_id', 'token_id')})
        bank = int(load_config(self.directory / 'simulated-bank.json')['signing_secret'], 16)
        port = self.server.server_port
        services, users = {}, []
        for guardian, config in configs.items():
            config.update(policy, assets=self.adapter.config['assets'], bank_public_key=curve.mul(bank)[1:].hex(),
                          policy_asset=policy_asset, historical_approval_policies=history,
                          # Incoming operators honor the same case authorities.
                          case_authority_keys=self.store.config.get('case_authority_keys', {}))
            private_json(self.directory / guardian / 'service.json', config)
            services[guardian] = self._launch_institution(guardian, port)
            login = next(value for value in credentials if value['username'] == guardian)
            users.append({'id': guardian, 'username': guardian, 'name': display_name(guardian),
                          'password': login['password'], 'role': 'institutionguardian', 'institution_id': guardian, 'tenant': 'bank'})
        self.store.register_users(users)
        known = {user['id'] for user in self.store.config['users']}
        self.store.config['users'].extend(user for user in users if user['id'] not in known)
        save_config(self.directory / 'web.json', self.store.config)
        manifest = dict(policy, institutions=services)
        manifests = self.adapter.config.setdefault('federation_manifests', [])
        manifests[:] = [entry for entry in manifests if entry['policy_version'] != policy['policy_version']]
        manifests.append(manifest)
        self.persist_adapter()
        return {'policy': policy, 'institutions': services}

    def institution_status(self):
        """Demo: whether each current institution's service is running."""
        return [{'id': guardian, 'online': guardian in self.institution_processes
                 and self.institution_processes[guardian].poll() is None}
                for guardian in self.adapter.config['guardian_order']]

    def set_institution_online(self, guardian, online):
        """Demo: stop or restart one institution's whole service, as if it went
        offline. It keeps its address, so nothing that calls it changes."""
        if guardian not in self.adapter.config['guardian_order']:
            raise ValueError('not a current operator')
        with self.institution_lock:
            return self._set_institution_online(guardian, online)

    def _set_institution_online(self, guardian, online):
        process = self.institution_processes.get(guardian)
        running = process is not None and process.poll() is None
        if online and not running:
            from urllib.parse import urlsplit
            endpoint = self.institution_endpoints[guardian]
            self._launch_institution(guardian, self.server.server_port, urlsplit(endpoint['url']).port)
            if self.institution_endpoints[guardian]['url'] != endpoint['url']:
                raise RuntimeError('operator restarted at a different address')
        elif not online and running:
            self.processes.stop(process, timeout=5)
        return self.institution_status()

    def _wallet(self, rpc_url, name):
        if name not in self.node.listwallets():
            if name in {item['name'] for item in self.node.listwalletdir()['wallets']}:
                self.node.loadwallet(name)
            else:
                self.node.createwallet(name, False, False, '', False, False)
        return RPC(rpc_url + '/wallet/' + name)

    def outside_address(self):
        """Demo: an address in a wallet no bank manages, so none has registered it."""
        return self._wallet(self.adapter.config['rpc_url'], 'outside').getnewaddress('', 'blech32')

    def retire_institutions(self, guardians):
        for guardian in guardians:
            process = self.institution_processes.get(guardian)
            if process is not None:
                self.processes.stop(process, timeout=5)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        if self.mesh:
            self.mesh.close()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server.drain_handlers(timeout=60)
        # Stop workers before closing RPC or the databases they use.
        for thread in (getattr(self, 'miner', None), getattr(self.server, 'worker', None)):
            if thread is not None:
                thread.join(timeout=10)
        if getattr(self, 'observer', None) is not None:
            self.observer.close()
        if self.node:
            try:
                self.node.stop()
            except Exception:
                pass
        try:
            self.processes.close()
        finally:
            if self.cluster:
                self.cluster.close()
        for thread in (getattr(self, 'miner', None), getattr(self.server, 'worker', None)):
            if thread is not None:
                thread.join(timeout=10)
                if thread.is_alive():
                    raise RuntimeError('owned service worker did not stop')
        if self.server and not self.server.drain_handlers(timeout=15):
            raise RuntimeError('owned HTTP handler did not stop; databases remain open')
        if getattr(self, 'store', None) is not None:
            self.store.close()
        if getattr(self, 'adapter', None) is not None:
            self.adapter.db.close()



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', help='new private runtime directory; must be empty')
    parser.add_argument('--resume', type=Path, help='resume an existing sandbox with its original chain and keys')
    # Prefer binaries kept beside the runtimes; /tmp is cleared at boot.
    kept = state_directory()
    daemon = kept / 'bin' / 'elementsd'
    library = kept / 'secp' / 'lib' / 'libsecp256k1.so'
    parser.add_argument('--daemon', default=str(daemon) if daemon.exists() else '/tmp/elements-audit-native-build/bin/elementsd')
    parser.add_argument('--library', default=str(library) if library.exists() else '/tmp/elements-audit-secp/lib/libsecp256k1.so')
    parser.add_argument('--port', type=int, default=0)
    options = parser.parse_args()
    if options.resume and options.directory:
        parser.error('--resume and --directory are mutually exclusive')
    if not options.resume and options.directory and Path(options.directory).exists() and any(Path(options.directory).iterdir()):
        parser.error('use a new empty directory; existing chain or reserve state is never overwritten')
    if not (options.resume or options.directory):
        runtimes = state_directory() / 'runtimes'
        runtimes.mkdir(mode=0o700, exist_ok=True)
    directory = options.resume or options.directory or tempfile.mkdtemp(prefix='elements-institutional-', dir=runtimes)
    sandbox = Sandbox(directory, options.daemon, options.library)
    def stop(*_):
        sandbox.stop.set()
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        if options.resume:
            sandbox.resume(options.port)
        else:
            sandbox.start(options.port)
        while not sandbox.stop.wait(1):
            pass
    finally:
        sandbox.close()


if __name__ == '__main__':
    main()

"""What the shared ledger itself records about each transaction.

Everything here is read from the node's own blocks and checked on the spot:
the institutions' authorization signatures are verified against the policy
keys, and block signatures against the federation's block keys. Amounts are
reported only as hidden or visible, because that is all the chain shows.
"""

import threading

from test_framework import messages
from test_framework.messages import CBlock, from_hex, ser_uint256
from test_framework.script import CScript
from .authorization import authorization_digest, decode_policy, policy_bytes
from .treasury import NativeECDSA


SIGNATURE_SIZE = 65  # policy index byte + 64-byte BIP340 signature


class LedgerView:
    def __init__(self, adapter):
        messages.THRESHOLD_AUDIT = True
        self.adapter = adapter
        self.ecdsa = NativeECDSA(adapter.curve)
        self.lock = threading.Lock()
        # Mined blocks never change in this single-node sandbox; summaries are
        # cached by hash and the walk back follows each block's parent hash.
        self.blocks = {}

    def _manifests(self):
        config = self.adapter.config
        return [*config.get('federation_manifests', []), config]

    def _names(self):
        """Authorization and block-signing keys of every group this service has run."""
        approval, block = {}, {}
        config = self.adapter.config
        for policy in config.get('historical_approval_policies', {}).values():
            for guardian, key in policy.get('public_keys', {}).items():
                approval.setdefault(key, guardian)
        for manifest in self._manifests():
            for guardian, key in manifest.get('approval_public_keys', {}).items():
                approval[key] = guardian
            for guardian, key in manifest.get('block_public_keys', {}).items():
                block[key] = guardian
        return approval, block

    def _policies(self, current):
        """Every authorization policy the chain may have used, newest first."""
        candidates = [current] if current else []
        config = self.adapter.config
        groups = [(m.get('approval_public_keys'), m.get('guardian_order'), m.get('threshold')) for m in self._manifests()]
        groups += [(p.get('public_keys'), list(p.get('public_keys') or {}), p.get('threshold'))
                   for p in config.get('historical_approval_policies', {}).values()]
        for keys, order, threshold in groups:
            try:
                policy = policy_bytes(keys, order, threshold)
            except (TypeError, ValueError, KeyError):
                continue
            if policy not in candidates:
                candidates.append(policy)
        return candidates

    def _authorization(self, transaction, genesis, policies, names):
        body = transaction.wit.vchAuthorization
        if not body:
            return None
        expiry = int.from_bytes(body[:4], 'little')
        entries = [(body[offset], body[offset + 1:offset + SIGNATURE_SIZE])
                   for offset in range(4, len(body) - SIGNATURE_SIZE + 1, SIGNATURE_SIZE)]
        for policy in policies:
            threshold, keys = decode_policy(policy)
            if len(entries) != threshold or any(index >= len(keys) for index, _ in entries):
                continue
            digest = authorization_digest(genesis, policy, transaction, expiry)
            if all(self.adapter.curve.verify_signature(keys[index], digest, signature) for index, signature in entries):
                return {'expiry_height': expiry, 'verified': True, 'threshold': threshold, 'authorizers': len(keys),
                        'signers': [names.get(keys[index].hex(), f'authorizer {index + 1}') for index, _ in entries]}
        return {'expiry_height': expiry, 'verified': False, 'signers': []}

    def _block_signers(self, block, names):
        stack = block.m_signblock_witness.stack
        if len(stack) < 3:
            return None  # set up before the federation took over block signing
        keys = [item for item in list(CScript(stack[-1]))[1:-2] if isinstance(item, bytes)]
        unsigned = from_hex(CBlock(), block.serialize().hex())
        unsigned.m_signblock_witness.stack = []
        unsigned.rehash()
        digest = ser_uint256(unsigned.sha256)
        signers = []
        for signature in stack[1:-1]:
            for key in keys:
                if self.ecdsa.verify(key, digest, signature):
                    signers.append(names.get(key.hex(), 'unknown signer'))
                    break
        return signers

    def _summarize(self, block_hash, genesis, policies, approval_names, block_names):
        block = from_hex(CBlock(), self.adapter.node.getblock(block_hash, 0))
        transactions = []
        for transaction in block.vtx[1:]:
            transaction.rehash()
            outputs = transaction.vout
            witnesses = transaction.wit.vtxoutwit
            transactions.append({
                'txid': transaction.hash,
                'inputs': len(transaction.vin),
                'outputs': sum(1 for output in outputs if bytes(output.scriptPubKey)),
                'hidden_amounts': sum(1 for output in outputs
                                      if bytes(output.scriptPubKey) and output.nValue.vchCommitment[:1] in (b'\x08', b'\x09')),
                'recovery_packets': sum(1 for witness in witnesses if witness.vchAuditProof),
                'issues_tokens': any(not inp.assetIssuance.isNull() for inp in transaction.vin),
                'burns_tokens': any(bytes(output.scriptPubKey) == b'\x6a' for output in outputs),
                'authorization': self._authorization(transaction, genesis, policies, approval_names),
            })
        return {'hash': block_hash, 'previous': f'{block.hashPrevBlock:064x}', 'height': block.block_height,
                'time': block.nTime, 'signers': self._block_signers(block, block_names), 'transactions': transactions}

    def recent(self, limit=12, scan=600):
        """The latest `limit` transactions, looking back at most `scan` blocks."""
        node = self.adapter.node
        info = node.getblockchaininfo()
        genesis = node.getblockhash(0)
        current = bytes.fromhex(info.get('tx_authorization') or '')
        approval_names, block_names = self._names()
        policies = self._policies(current)
        with self.lock:
            block_hash, found, blocks, latest = info['bestblockhash'], [], 0, None
            while block_hash != genesis and blocks < scan and len(found) < limit:
                summary = self.blocks.get(block_hash)
                if summary is None or any(item['authorization'] and not item['authorization']['verified']
                                          for item in summary['transactions']):
                    # Unverified entries are retried: a newer policy may explain them.
                    summary = self.blocks[block_hash] = self._summarize(block_hash, genesis, policies,
                                                                        approval_names, block_names)
                latest = latest or summary
                for item in summary['transactions']:
                    found.append(dict(item, height=summary['height'], time=summary['time'],
                                      block_signers=summary['signers']))
                block_hash, blocks = summary['previous'], blocks + 1
        threshold, keys = decode_policy(current) if current else (0, [])
        return {
            'height': info['blocks'],
            'latest_block': latest and {'height': latest['height'], 'time': latest['time'], 'signers': latest['signers']},
            'policy': {'threshold': threshold,
                       'authorizers': [approval_names.get(key.hex(), f'authorizer {index + 1}') for index, key in enumerate(keys)]},
            'blocks_scanned': blocks,
            'transactions': found[:limit],
        }

    def unauthorized_attempt(self):
        """Have a bank wallet sign a valid payment to itself, then offer it to
        the node with and without the institutions' authorization. Neither copy
        is broadcast unless the node would refuse it anyway."""
        adapter = self.adapter
        wallet = adapter.sponsor
        funded = wallet.walletcreatefundedpsbt([], [{wallet.getnewaddress('', 'bech32'): '0.0001'}], 0,
                                               {'fee_rate': 2, 'lockUnspents': False})['psbt']
        final = wallet.finalizepsbt(wallet.walletprocesspsbt(funded)['psbt'])
        if not final.get('complete'):
            raise ValueError('the bank wallet could not sign the test payment')
        raw = final['hex']
        transaction = from_hex(messages.CTransaction(), raw)
        transaction.rehash()
        plain = adapter.node.testmempoolaccept([raw], 0)[0]
        result = {'txid': transaction.hash,
                  'without': {'accepted': bool(plain['allowed']), 'reason': plain.get('reject-reason')}}
        if not plain['allowed']:
            # Show the refusal is real: the node turns down the actual broadcast too.
            try:
                adapter.node.sendrawtransaction(raw, 0)
                result['without']['broadcast_refused'] = False
            except Exception as error:
                result['without']['broadcast_refused'] = True
                result['without']['broadcast_error'] = str(error)[:200]
        try:
            authorized = adapter.authorize(raw)
        except ValueError as error:
            result['with'] = {'accepted': False, 'reason': str(error)[:300]}
            return result
        check = adapter.node.testmempoolaccept([authorized], 0)[0]
        approval_names, _ = self._names()
        info = adapter.node.getblockchaininfo()
        current = bytes.fromhex(info.get('tx_authorization') or '')
        detail = self._authorization(from_hex(messages.CTransaction(), authorized), adapter.node.getblockhash(0),
                                     [current] if current else [], approval_names)
        result['with'] = {'accepted': bool(check['allowed']), 'reason': check.get('reject-reason'),
                          'authorization': detail}
        return result

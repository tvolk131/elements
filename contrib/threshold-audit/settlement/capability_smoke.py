"""Explicit-credential demo acceptance driver; never used by the web application.

Creates small TEST-ASSET transfers and disclosure cases in the selected runtime.
Keeps its own recipient key encrypted in private fixture files. Existing pending
requests are not approved or executed. Run against a disposable or authorized demo.
"""
import argparse
import copy
import json
from pathlib import Path
import secrets
import time
from decimal import Decimal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from curve import Curve, random_scalar
from guardian_service import atomic_write
from .disclosure_recipient import open_bundle
from .authorization import registration_digest
from .elements_adapter import ElementsAdapter, RPC
from .runtime import load_config
from .smoke import Pilot
from sealed_delivery import canonical


def run(directory):
    directory=Path(directory); pilot=Pilot(directory)
    adapter=load_config(directory/'adapter.json');curve=Curve(adapter['library']);node=RPC(adapter['rpc_url'])
    # Wallets outside the outbox still need the federation's authorization to send.
    chain=ElementsAdapter(adapter);bank=int(load_config(directory/'simulated-bank.json')['signing_secret'],16);genesis=node.getblockhash(0)
    chain.registrar=lambda script:curve.sign(bank,registration_digest(genesis,script))
    evidence=directory/'capability-smoke';evidence.mkdir(mode=0o700,exist_ok=True)
    state_path=evidence/'state.json';state=json.loads(state_path.read_text()) if state_path.exists() else {}
    def save():atomic_write(state_path,state)
    def settle(label,creator,body,checker='bank-approver'):
        if label not in state:
            op=pilot.call(creator,'/api/transfers',body);state[label]=op['id'];save()
        op=pilot.call(checker,'/api/operations/'+state[label])
        if op['state']=='awaiting_approval':op=pilot.approve(op,checker)
        elif op['state']=='ready':op=pilot.call(checker,'/api/operations/'+op['id']+'/execute',{})
        return pilot.wait(op)
    try:
        if 'bank_transfer' not in state:
            route=pilot.call('acme-maker','/api/beneficiaries/resolve',{'account_id':'acme-main','currency':'EUR','reference':'initech-main@bank-b'})
            body={'account_id':'acme-main','currency':'EUR','amount':'1.23','route_id':route['payload']['id']}
        else:body={}
        transfer=settle('bank_transfer','acme-maker',body)
        incoming=pilot.call('initech-maker','/api/operations/'+transfer['id'])
        assert incoming['incoming'] and not incoming['allowed_actions']
        assert incoming.get('approval_workflow') is None
        if 'address_transfer' not in state:
            address=pilot.call('acme-maker','/api/receive-address',{'account_id':'acme-main','currency':'EUR'})['address']
            pilot.call('initech-maker','/api/beneficiaries/validate-address',{'address':address})
            body={'account_id':'initech-main','currency':'EUR','amount':'0.01','address':address}
        returned=settle('address_transfer','initech-maker',body,'bank-b-approver')
        # Exercise receiving a real supported asset from outside the application
        # outbox. Funding this fixture wallet is itself an approved app payment.
        external_name='capability-external-wallet'
        if external_name not in {item['name'] for item in node.listwalletdir()['wallets']}:
            node.createwallet(external_name,False,False,'',False,False)
        if external_name not in node.listwallets():node.loadwallet(external_name)
        external=RPC(adapter['rpc_url']+'/wallet/'+external_name)
        if 'external_address' not in state:
            state['external_address']=external.getnewaddress('capability-test','blech32');save()
        if 'external_fee_txid' not in state:
            fee_address=external.getnewaddress('capability-fees','bech32')
            state['external_fee_txid']=chain.wallet_send(chain.sponsor,{fee_address:1});save()
        outside_funding=settle('external_funding','acme-maker',{'account_id':'acme-main','currency':'EUR','amount':'0.02','address':state['external_address']})
        if 'external_receipt_txid' not in state:
            receiver=pilot.call('initech-maker','/api/receive-address',{'account_id':'initech-main','currency':'EUR'})['address']
            asset=next(a['asset_id'] for a in pilot.call('initech-maker','/api/dashboard')['assets'] if a['currency']=='EUR')
            state['external_receipt_txid']=chain.wallet_send(external,{receiver:Decimal('0.01')},asset);save()
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            received=next((op for op in pilot.call('initech-maker','/api/dashboard')['operations'] if op['kind']=='receipt' and op['txid']==state['external_receipt_txid']),None)
            if received:break
            time.sleep(.3)
        else:raise AssertionError('confirmed outside receipt was not credited')
        assert received['amount_minor']==1 and received['state']=='settled'
        try:pilot.call('initech-maker','/api/operations/'+next(op['id'] for op in pilot.call('acme-maker','/api/dashboard')['operations'] if op['id'] not in (transfer['id'],returned['id'])))
        except (RuntimeError,StopIteration):pass
        else:raise AssertionError('receiving customer could read an unrelated payment')
        key_path=evidence/'recipient-key.json';password_path=evidence/'recipient-password.json'
        if not key_path.exists():
            secret=random_scalar();public=curve.mul(secret).hex();password=secrets.token_urlsafe(24)
            salt,nonce=secrets.token_bytes(16),secrets.token_bytes(12)
            aes=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=210000).derive(password.encode())
            base={'format':'concord-recipient-key-v1','user_id':'demo-recipient','public_key':public}
            ciphertext=AESGCM(aes).encrypt(nonce,secret.to_bytes(32,'big'),canonical(base))
            atomic_write(password_path,{'password':password});atomic_write(key_path,dict(base,salt=salt.hex(),nonce=nonce.hex(),ciphertext=ciphertext.hex()))
        key=json.loads(key_path.read_text());password=json.loads(password_path.read_text())['password']
        from .disclosure_recipient import unlock_key
        secret=unlock_key(key,password)
        pilot.call('demo-recipient','/api/disclosures/recipient-key',{'public_key':key['public_key']})
        def disclose(label,operation_id):
            if label not in state:
                targets=pilot.call('bank-compliance','/api/disclosure-targets/'+operation_id)['outputs']
                if not targets:raise AssertionError('payment has no eligible confidential output')
                selected=next((target for target in targets if target['label']=='Payment destination'),targets[0])
                case=pilot.call('bank-compliance','/api/disclosures',{'operation_id':operation_id,'targets':[{'txid':selected['txid'],'output_index':selected['output_index']}],
                     'recipient_id':'demo-recipient','recipient_key':key['public_key'],'authority':'Capability demo acceptance',
                     'reason':'Explicit test-fixture authorization to verify recipient-encrypted recovery; no real investigation or money.','expires_in':3600})
                state[label]=case['id'];save()
            case=pilot.call('bank-compliance','/api/disclosures/'+state[label])
            assert case['threshold']==pilot.call('bank-compliance','/api/dashboard')['network']['audit_threshold']
            members=pilot.call('bank-compliance','/api/disclosures')['members']
            for member in members[:case['threshold']]:
                if member not in case['approved_members']:
                    case=pilot.call(f'audit-guardian-{member}','/api/disclosures/'+case['id']+'/approve',{})
            if case['state']!='delivered':case=pilot.call('bank-compliance','/api/disclosures/'+case['id']+'/release',{})
            assert case['state']=='delivered',case
            try:pilot.call('bank-compliance','/api/disclosures/'+case['id']+'/bundle')
            except RuntimeError:pass
            else:raise AssertionError('requester could download recipient-only package')
            bundle=pilot.call('demo-recipient','/api/disclosures/'+case['id']+'/bundle')
            atomic_write(evidence/(label+'-bundle.json'),bundle)
            opened=open_bundle(curve,secret,'demo-recipient',bundle,node)
            assert opened['chain_verified']
            atomic_write(evidence/(label+'-openings.json'),opened)
            return case,opened
        case,opened=disclose('current_case',transfer['id'])
        assert opened['outputs'][0]['amount_base_units']=='123000000',opened
        # Find a payment predating the current federation's last activation.
        historical=next((op for op in reversed(pilot.call('bank-compliance','/api/dashboard')['operations'])
                         if op.get('txid') and op['kind'] in ('deposit','transfer') and op['state']=='settled'
                         and op['id'] not in (transfer['id'],returned['id'])),None)
        historical_result=None
        if historical:
            historical_case,historical_opened=disclose('historical_case',historical['id'])
            historical_result={'id':historical_case['id'],'outputs':[{'txid':o['txid'],'output_index':o['output_index'],'amount_base_units':o['amount_base_units']} for o in historical_opened['outputs']],'threshold':historical_case['threshold']}
        bank_b=pilot.call('initech-maker','/api/dashboard')
        assert all(b['chain_reconciles'] for b in bank_b['balances'])
        reserve=pilot.call('bank-compliance','/api/dashboard')['reserves']
        assert all(r['cash_reconciles'] and r['liabilities_reconcile'] and r['supply_reconciles'] for r in reserve)
        result={'status':'passed','genesis_hash':node.getblockhash(0),'transfers':[{'id':op['id'],'txid':op['txid'],'state':op['state']} for op in (transfer,returned,outside_funding)],
                'external_receipt':{'txid':received['txid'],'credited_minor':received['amount_minor']},
                'disclosure':{'id':case['id'],'threshold':case['threshold'],'approved':len(case['approved_members']),'chain_verified':True},
                'historical_disclosure':historical_result,'bank_b_balance_reconciles':True,'reserves_reconcile':True,
                'recipient_artifacts':str(evidence)}
        atomic_write(directory/'capability-smoke-result.json',result)
        print(json.dumps(result,indent=2))
    finally:curve.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory');run(parser.parse_args().directory)

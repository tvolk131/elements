"""Failure-oriented capability tests. All keys and chain data here are fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import time
import unittest

from chunked import encrypt_chunked, partial_decrypt_chunked, combine_chunked, verify_chunked
from curve import Curve, random_scalar, scalar_bytes
from disclosure import Policy, Request, Approval, authorize
from guardian_service import statement_json, disclosure_from, statement_from
from recovery import Opening, Statement, digest, index_bytes
from sealed_delivery import seal, unseal
from threshold import simulate_keygen, PartialDecryption
from .approval import ApprovalVerifier
from .disclosures import Disclosures
from .directory import Directory
from .receipts import Receipts
from .store import Settlement, Problem
from .test_settlement import TestChain

LIBRARY = os.environ.get('THRESHOLD_AUDIT_SECP256K1','/tmp/elements-audit-secp/lib/libsecp256k1.so')
def named(label): return hashlib.sha256(label.encode()).digest()

class Guardian:
    def __init__(self, audit, member, share, identity):
        self.audit,self.member,self.share,self.identity=audit,member,share,identity
        self.approvals=0
    def request(self, action, credentials=None, **payload):
        policy, request=disclosure_from(payload)
        if action=='approve':
            self.approvals+=1
            return {'member':self.member,'signature':self.audit.curve.sign(self.identity,request.binding()).hex()}
        if action!='disclose-sealed': raise ValueError('unexpected action')
        authorize(self.audit.curve,policy,request,tuple(Approval(a['member'],bytes.fromhex(a['signature'])) for a in payload['approvals']),int(time.time()))
        packet=self.audit.packet; statement=statement_from(payload['statement'])
        if not verify_chunked(self.audit.curve,statement,packet): raise ValueError('packet')
        partial=partial_decrypt_chunked(self.audit.curve,statement,packet,self.audit.committee,self.share,request.binding())
        checkpoint={'member':self.member,'sequence':1,'head':named('checkpoint').hex()}
        checkpoint['signature']=self.audit.curve.sign(self.identity,digest(b'guardian-checkpoint',index_bytes(self.member),(1).to_bytes(8,'big'),bytes.fromhex(checkpoint['head']))).hex()
        value={'member':partial.member,'committee_binding':partial.committee_binding.hex(),'request_binding':partial.request_binding.hex(),
               'points':[p.hex() for p in partial.points],'proofs':[[scalar_bytes(x).hex() for x in pair] for pair in partial.proofs],'checkpoint':checkpoint}
        return seal(self.audit.curve,self.identity,request.recipient_key,request.binding(),self.member,value)

class CapabilitiesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(LIBRARY).exists(): raise unittest.SkipTest('native secp256k1 library required')
        cls.curve=Curve(LIBRARY)
        cls.committee,cls.shares=simulate_keygen(cls.curve,(1,2,3),2)
        cls.opening=Opening(named('capability asset'),12_000_000_000,12345,67890)
        A=cls.curve.asset_commitment(cls.opening.asset,cls.opening.asset_blinder)
        cls.statement=Statement(named('chain'),named('tx-template'),0,b'\x51',A,cls.curve.value_commitment(A,cls.opening.amount,cls.opening.value_blinder),cls.committee.public_key,(cls.opening.asset,))
        cls.packet=encrypt_chunked(cls.curve,cls.statement,cls.opening)
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'curve'): cls.curve.close()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='concord-capability-test-')
        self.chain=TestChain()
        keys={f'i{i}':self.curve.mul(100+i)[1:].hex() for i in (1,2,3)}
        self.users={u['id']:u for u in [
            {'id':'compliance-a','username':'compliance-a','role':'bankcompliance','tenant':'bank'},
            {'id':'compliance-b','username':'compliance-b','role':'bankcompliance','tenant':'bank-b'},
            {'id':'outsider','username':'outsider','role':'bankcompliance','tenant':'other-bank'},
            {'id':'federal','username':'federal','role':'federationcompliance','tenant':'federation'},
            {'id':'recipient','username':'recipient','role':'auditor','tenant':'bank'},
            {'id':'maker','username':'maker','role':'bankmaker','tenant':'bank'},
            *[{'id':f'g{i}','username':f'g{i}','role':'auditguardian','tenant':'federation','audit_member':i} for i in (1,2,3)]
        ]}
        for user in self.users.values(): user.update(name=user['id'],password='fixture-password')
        self.users['compliance-a']['name']='Bank A Compliance'
        accounts=[{'id':'a','name':'A Customer','tenant':'a','bank_tenant':'bank','addresses':{'EUR':'conf-a'}},
                  {'id':'b','name':'B Customer','tenant':'b','bank_tenant':'bank-b','addresses':{'EUR':'conf-b'}}]
        self.store=Settlement(Path(self.temp.name)/'store.sqlite',self.chain,ApprovalVerifier(self.curve,keys,2),config={'accounts':accounts,'users':list(self.users.values())})
        self.txid=named('confirmed payment').hex(); self.operation_id='a'*32
        op={'id':self.operation_id,'kind':'transfer','state':'settled','account_id':'a','to_account_id':'b','destination':'conf-b','txid':self.txid,'tenant':'a'}
        self.store.db.execute('INSERT INTO operations VALUES(?,?,?,?,?)',(op['id'],'transfer','settled','a',json.dumps(op)))
        identities=tuple((i,self.curve.mul(200+i)[1:]) for i in (1,2,3))
        self.binding=named('configuration')
        key=SimpleNamespace(version=1,public_key=self.committee.public_key,committee=self.committee)
        configuration=SimpleNamespace(binding=lambda:self.binding,key=lambda version:key,active_key=key,identities=identities)
        self.audit=SimpleNamespace(curve=self.curve,current_config=lambda:configuration,committee=self.committee,packet=self.packet)
        self.audit.node=SimpleNamespace(getrawtransaction=lambda txid,verbose:{'blockhash':named('block').hex(),'confirmations':3,'vout':[{'n':0,'valuecommitment':self.statement.value_commitment.hex(),'assetcommitment':self.statement.asset_commitment.hex(),'scriptPubKey':{'hex':'51'}}]},getblockhash=lambda height:named('block').hex(),validateaddress=lambda address:{'scriptPubKey':'51'})
        self.audit.cluster=SimpleNamespace(guardians={i:Guardian(self.audit,i,self.shares[i-1],200+i) for i in (1,2,3)},approvers={i:{} for i in (1,2,3)})
        self.audit.disclosure_context=lambda txid,index:{'txid':txid,'output_index':index,'creation_block':named('block').hex(),'creation_height':42,'key_version':1,'configuration':self.binding.hex(),'statement':statement_json(self.statement),'packet':self.packet.to_bytes().hex(),'committee':{'epoch':self.committee.epoch,'members':list(self.committee.members),'commitments':[c.hex() for c in self.committee.commitments]},'identities':[[i,p.hex()] for i,p in identities]}
        self.disclosures=Disclosures(self.store,self.audit)
        self.recipient_secret=333
        self.disclosures.register_key(self.users['recipient'],{'public_key':self.curve.mul(self.recipient_secret).hex()})
    def tearDown(self): self.store.close(); self.temp.cleanup()
    def create(self,user='compliance-a'):
        return self.disclosures.create(self.users[user],{'operation_id':self.operation_id,'targets':[{'txid':self.txid,'output_index':0}],'recipient_id':'recipient','recipient_key':self.curve.mul(self.recipient_secret).hex(),'authority':'Bank A Compliance','reason':'Investigate the selected test payment','expires_in':3600})
    def approve(self,case,member): return self.disclosures.approve(self.users[f'g{member}'],case['id'])
    def delivered(self):
        case=self.create();self.approve(case,1);self.approve(case,2)
        self.disclosures.release(self.users['compliance-a'],case['id'])
        return self.disclosures.bundle(self.users['recipient'],case['id'])
    def test_explicit_approvals_sealed_recipient_recovery_and_wrong_key(self):
        case=self.create()
        self.assertTrue(all(g.approvals==0 for g in self.audit.cluster.guardians.values()))
        with self.assertRaises(Problem):self.disclosures.release(self.users['compliance-a'],case['id'])
        self.approve(case,1)
        with self.assertRaises(Problem):self.disclosures.release(self.users['compliance-a'],case['id'])
        self.approve(case,2); self.disclosures.release(self.users['compliance-a'],case['id'])
        with self.assertRaises(Problem):self.disclosures.bundle(self.users['compliance-a'],case['id'])
        bundle=self.disclosures.bundle(self.users['recipient'],case['id']); output=bundle['outputs'][0]
        partials=[]
        for member,envelope in output['sealed_partials'].items():
            self.assertNotIn('points',envelope)
            identity=dict(output['identities'])[int(member)]
            with self.assertRaises(ValueError):unseal(self.curve,444,bytes.fromhex(identity),envelope,bytes.fromhex(output['request_binding']),int(member))
            value=unseal(self.curve,self.recipient_secret,bytes.fromhex(identity),envelope,bytes.fromhex(output['request_binding']),int(member))
            partials.append(PartialDecryption(value['member'],bytes.fromhex(value['committee_binding']),bytes.fromhex(value['request_binding']),tuple(bytes.fromhex(p) for p in value['points']),tuple(tuple(int(s,16) for s in p) for p in value['proofs'])))
        self.assertEqual(combine_chunked(self.curve,self.statement,self.packet,self.committee,tuple(partials),bytes.fromhex(output['request_binding'])),self.opening)
        stored=json.loads(self.store.db.execute('SELECT data FROM disclosure_cases WHERE id=?',(case['id'],)).fetchone()[0])
        self.assertNotIn('asset_blinder',json.dumps(stored)); self.assertNotIn('value_blinder',json.dumps(stored))
    def test_bank_scope_ownership_and_recipient_registration(self):
        with self.assertRaises(Problem):self.create('outsider')
        self.assertTrue(self.disclosures.targets(self.users['compliance-b'],self.operation_id)['outputs'])
        with self.assertRaises(Problem):self.disclosures.register_key(self.users['maker'],{'public_key':self.curve.mul(999).hex()})
        case=self.create()
        with self.assertRaises(Problem):self.disclosures.get(self.users['outsider'],case['id'])
        with self.assertRaises(Problem):self.disclosures.approve(self.users['maker'],case['id'])
    def test_decline_not_veto_expiry_rotation_and_restart(self):
        case=self.create(); self.disclosures.approve(self.users['g1'],case['id'],decline=True)
        self.approve(case,2); ready=self.approve(case,3); self.assertEqual(ready['state'],'ready')
        self.binding=named('new configuration')
        self.assertEqual(self.disclosures.public(self.users['compliance-a'],self.disclosures.load(case['id']))['state'],'membership_changed')
        with self.assertRaises(Problem):self.disclosures.release(self.users['compliance-a'],case['id'])
        restored=Disclosures(self.store,self.audit)
        self.assertEqual(restored.load(case['id'])['manifest_hash'],case['manifest_hash'])
        second=self.create()
        from unittest.mock import patch
        with patch('settlement.disclosures.time.time', return_value=time.time()+4000):
            with self.assertRaises(Problem):restored.approve(self.users['g1'],second['id'])
    def test_request_delivery_mode_and_recipient_are_bound(self):
        case=self.create();output=self.disclosures.load(case['id'])['outputs'][0]
        # People see the requester's name; the signed manifest keeps the ID.
        self.assertEqual((case['requester_id'],case['requester_name']),('compliance-a','Bank A Compliance'))
        self.assertNotIn('requester_name',self.disclosures.load(case['id'])['manifest'])
        _,request=disclosure_from(output)
        legacy=Request(request.policy_binding,request.statement_binding,request.packet_binding,request.case_reference,request.recipient_key,request.expires_at)
        self.assertNotEqual(request.binding(),legacy.binding())
        tampered=copy.deepcopy(output);tampered['request']['recipient_key']=self.curve.mul(444).hex()
        self.assertNotEqual(request.binding(),disclosure_from(tampered)[1].binding())
    def test_signed_directory_routes_are_source_bound_single_use_and_cross_bank(self):
        class Wallet:
            def getnewaddress(self,*args):return 'el1fixture'+('a'*80)
            def getaddressinfo(self,address):return {'ismine':False}
        self.chain.wallets={'a':Wallet(),'b':Wallet()}
        self.chain.node=SimpleNamespace(validateaddress=lambda address:{'isvalid':True,'confidential_key':self.curve.mul(1).hex()})
        directory=Directory(self.store,{'bank':700,'bank-b':701});self.store.directory=directory
        route=directory.resolve(self.users['maker'],{'account_id':'a','currency':'EUR','reference':'b@bank-b'})
        self.assertTrue(route['verified']);self.assertEqual(route['payload']['bank_id'],'bank-b')
        with self.assertRaises(Problem):
            with self.store.transaction():directory.consume(self.users['maker'],self.store.account('b'),'EUR',route['payload']['id'],'case')
        with self.store.transaction():target,_,_,_=directory.consume(self.users['maker'],self.store.account('a'),'EUR',route['payload']['id'],'case')
        self.assertEqual(target['id'],'b')
        with self.assertRaises(Problem):
            with self.store.transaction():directory.consume(self.users['maker'],self.store.account('a'),'EUR',route['payload']['id'],'other-case')
        self.assertEqual(directory.address('el1fixture'+('a'*80)),None)
    def test_observed_external_receipt_is_credited_once_after_confirmation(self):
        asset=self.chain.assets()[0]['asset_id']
        events=[{'txid':'c'*64,'vout':0,'category':'receive','asset':asset,'amount':'1.23','confirmations':0}]
        wallet=SimpleNamespace(listsinceblock=lambda *args:{'transactions':events,'removed':[],'lastblock':'d'*64})
        self.chain.wallets={'b':wallet};observer=Receipts(self.store)
        observer.poll();self.assertEqual(self.store.token_balance('b','EUR'),0)
        events[0]['confirmations']=1;observer.poll();observer.poll()
        self.assertEqual(self.store.token_balance('b','EUR'),123)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observed_receipts').fetchone()[0],1)

    def test_receiving_bank_cannot_select_external_senders_change(self):
        operation=self.store._operation(self.operation_id)
        operation.update(kind='receipt',account_id='b',to_account_id=None,output_index=0)
        self.store.save(operation)
        decoded=self.audit.node.getrawtransaction(self.txid,True)
        decoded['vout'].append(dict(decoded['vout'][0],n=1,scriptPubKey={'hex':'52'}))
        self.audit.node.getrawtransaction=lambda *args:decoded
        targets=self.disclosures.targets(self.users['compliance-b'],self.operation_id)
        self.assertEqual([o['output_index'] for o in targets['outputs']],[0])

    def test_disabling_recipient_blocks_new_releases(self):
        case=self.create();self.approve(case,1);self.approve(case,2)
        user=json.loads(self.store.db.execute('SELECT data FROM users WHERE id=?',('recipient',)).fetchone()[0])
        user['disabled']=True
        self.store.db.execute('UPDATE users SET data=? WHERE id=?',(self.store.encode(user),'recipient'))
        self.assertEqual(self.disclosures.public(self.users['compliance-a'],self.disclosures.load(case['id']))['state'],'recipient_unavailable')
        with self.assertRaises(Problem):self.disclosures.release(self.users['compliance-a'],case['id'])

if __name__=='__main__':
    import sys
    if len(sys.argv)==3 and sys.argv[1]=='--fixture':
        CapabilitiesTests.setUpClass();test=CapabilitiesTests();test.setUp()
        try:
            bundle=test.delivered()
            Path(sys.argv[2]).write_text(json.dumps({'bundle':bundle,'secret':f'{test.recipient_secret:064x}',
                'expected':{'asset_id':test.opening.asset[::-1].hex(),'amount_base_units':str(test.opening.amount),'asset_blinder':f'{test.opening.asset_blinder:064x}','value_blinder':f'{test.opening.value_blinder:064x}'},
                'generators':{test.opening.asset.hex():test.curve.asset_generator(test.opening.asset).hex()}},separators=(',',':')))
        finally:test.tearDown();CapabilitiesTests.tearDownClass()
    else:unittest.main()

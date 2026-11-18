"""Exercise the running REAL Elements sandbox through its authenticated API.

Only this test driver reads all fixture user/institution credentials. The web
application has no institution approval passphrases or federation spending keys.
"""

import argparse
import http.cookiejar
import json
from pathlib import Path
import time
import urllib.error
import urllib.request


class Pilot:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.ready = json.loads((self.directory / 'ready.json').read_text())
        self.base = self.ready['url'].rstrip('/')
        self.credentials = {user['username']: user for user in json.loads((self.directory / 'credentials.json').read_text())}
        self.clients = {}

    @staticmethod
    def request(opener, url, body=None, csrf=None):
        headers = {'Content-Type': 'application/json'}
        if csrf:
            headers['X-CSRF-Token'] = csrf
        request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            with opener.open(request, timeout=180) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f'HTTP {error.code}: {error.read().decode()}') from error

    def call(self, username, path, body=None):
        if username not in self.clients:
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            credential = self.credentials[username]
            session = self.request(opener, self.base + '/api/login', {'username': username, 'password': credential['password']})
            self.clients[username] = (opener, session['csrf'])
        opener, csrf = self.clients[username]
        return self.request(opener, self.base + path, body, csrf)

    def approve(self, operation, checker='bank-approver'):
        oid = operation['id']
        self.call(checker, f'/api/operations/{oid}/approve', {})
        self.credentials.update({user['username']: user for user in json.loads((self.directory / 'credentials.json').read_text())})
        policy = self.call(checker, '/api/dashboard')
        guardian_ids = [guardian['id'] for guardian in policy['guardians']][:policy['network']['operational_threshold']]
        for guardian in guardian_ids:
            reviewed = self.call(guardian, f'/api/operations/{oid}/prepare-approval', {})
            dashboard = self.call(guardian, '/api/dashboard')
            service = next(item for item in dashboard['guardians'] if item['id'] == guardian)['approval_url']
            signature = self.request(urllib.request.build_opener(), service + 'approve', {
                'operation': reviewed['approval_request'],
                'passphrase': self.credentials[guardian]['institution_approval_passphrase']})
            operation = self.call(guardian, f'/api/operations/{oid}/certificates', {'signature': signature})
        if operation['state'] != 'ready':
            raise AssertionError(operation)
        return self.call(checker, f'/api/operations/{oid}/execute', {})

    def wait(self, operation, states=('settled',), timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            operation = self.call('bank-approver', '/api/operations/' + operation['id'])
            if operation['state'] in states:
                return operation
            if operation.get('error'):
                raise AssertionError(f"{operation['kind']} {operation['state']}: {operation['error']}")
            time.sleep(.3)
        raise AssertionError('operation did not reach expected state: ' + str(operation))

    def deposit(self, currency, amount, account='acme-main'):
        operation = self.call('bank-maker', '/api/deposits', {'account_id': account, 'currency': currency, 'amount': amount})
        body = {'event_id': 'smoke-credit-' + operation['id'], 'kind': 'credit', 'currency': currency,
                'operation_id': operation['id'], 'amount': amount}
        self.call('bank-admin', '/api/bank/events', body)
        if not self.call('bank-admin', '/api/bank/events', body)['duplicate']:
            raise AssertionError('duplicate credit was applied twice')
        return self.wait(self.approve(operation))

    def bank_mode(self, currency, mode):
        return self.call('bank-admin', '/api/bank/events', {'event_id': 'mode-' + str(time.time_ns()),
                        'kind': 'payout_mode', 'currency': currency, 'outcome': mode})

    def redeem(self, currency, amount):
        operation = self.call('acme-maker', '/api/redemptions', {'account_id': 'acme-main', 'currency': currency,
                                 'amount': amount, 'beneficiary_id': 'acme-main-' + currency})
        return self.approve(operation, 'acme-approver')

    def run(self):
        operations = []
        for currency, amount in [('EUR', '400.00'), ('USD', '250.00')]:
            operation = self.deposit(currency, amount)
            operations.append(operation)
            print(currency, 'native issuance confirmed', operation['txid'], flush=True)
        transfer = self.call('acme-maker', '/api/transfers', {'account_id': 'acme-main', 'to_account_id': 'acme-treasury',
                              'currency': 'EUR', 'amount': '12.34'})
        transfer = self.wait(self.approve(transfer, 'acme-approver'))
        operations.append(transfer)
        print('confidential wallet transfer confirmed', transfer['txid'], flush=True)
        redeemed = self.wait(self.redeem('EUR', '100.00'))
        operations.append(redeemed)
        print('federation escrow, payout and burn confirmed', redeemed['txid'], flush=True)
        self.bank_mode('EUR', 'failed')
        failed = self.wait(self.redeem('EUR', '10.00'), states=('payment_failed',))
        refund = self.call('acme-maker', f"/api/operations/{failed['id']}/cancel", {})
        refund = self.wait(self.approve(refund, 'acme-approver'))
        operations.extend([failed, refund])
        print('definite failed payout returned through new federation quorum', refund['txid'], flush=True)
        self.bank_mode('EUR', 'settled')
        self.bank_mode('USD', 'unknown')
        unknown = self.wait(self.redeem('USD', '20.00'), states=('bank_unknown',))
        try:
            self.call('acme-maker', f"/api/operations/{unknown['id']}/cancel", {})
        except RuntimeError:
            pass
        else:
            raise AssertionError('ambiguous payout was refundable')
        self.call('bank-admin', '/api/bank/events', {'event_id': 'resolve-' + unknown['id'], 'kind': 'payout_result',
                  'currency': 'USD', 'operation_id': unknown['id'], 'outcome': 'settled'})
        unknown = self.wait(unknown)
        operations.append(unknown)
        self.bank_mode('USD', 'settled')
        print('ambiguous payout resolved once; native burn confirmed', unknown['txid'], flush=True)
        dashboard = self.call('auditor', '/api/dashboard')
        for reserve in dashboard['reserves']:
            for field in ('cash_reconciles', 'liabilities_reconcile', 'supply_reconciles'):
                if field in reserve and not reserve[field]:
                    raise AssertionError((field, reserve))
        # Cross-tenant operation data must remain inaccessible.
        try:
            self.call('globex-maker', '/api/operations/' + operations[0]['id'])
        except RuntimeError:
            pass
        else:
            raise AssertionError('cross-tenant operation was readable')
        result = {'status': 'passed', 'genesis_hash': self.ready['genesis_hash'],
                  'transactions': [{'kind': op['kind'], 'id': op['id'], 'txid': op.get('txid'), 'state': op['state']} for op in operations],
                  'reserves': dashboard['reserves']}
        (self.directory / 'smoke-result.json').write_text(json.dumps(result, indent=2))
        print('PASS: real Elements settlement and independent operator services; report:', self.directory / 'smoke-result.json', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    Pilot(args.directory).run()

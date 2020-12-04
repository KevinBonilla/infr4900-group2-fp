#!/usr/bin/env python
import os
import binascii
import datetime
import hashlib
import random
import copy
import ast
import sys
from flask import Flask, request, json, Response, render_template
from werkzeug.utils import secure_filename
app = Flask(__name__)
# ----------------------- BLOCKCHAIN CLASS ---------------------------------- #
class Blockchain:

    def __init__(self):
        self.chain = []
        self.difficulty = 3
        self.wallets = {}
        self.mempool = {}
        self.state = 0
        self.add()
        NULL_WALLET = {
            'public_key': 'f1f91c30722f64de1c004423c091ce33',
            'balance': 0.0,
            }
        self.wallets[NULL_WALLET['public_key']] = NULL_WALLET

###################### ADD CODE ONLY BETWEEN THESE LINES! #####################
    #This wallet is here to accept tokens contracts being uploaded, it has no private key because it cannot send tokens
    # any tokens sent here will be essentially gone forever

    
    def create_transaction(self, from_, to, amount, private_key, message=None):
        if not self._validate_transaction(from_, to, amount, private_key):
            return {'error': 'invalid transaction'}

        transaction = {
            'time': datetime.datetime.utcnow().timestamp(),
            'from': from_,
            'to': to,
            'amount': float(amount),
            'message': {},
        }

        transaction_id = self._hash_data(transaction)
        self.mempool[transaction_id] = transaction

        return {transaction_id: transaction}

    def create_wallet(self, contract_=None, priv=None, pub=None):
        if contract_==None:
            wallet = {
                'public_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'private_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'balance': 10.0,
            }
            self.wallets[wallet['public_key']] = wallet
            return wallet
        elif contract_ is not None:
            wallet = {
                'public_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'contract_code': contract_,
            }
            self.wallets[wallet['public_key']] = wallet 
            print(contract_)
            gas_price = self._calculate_gas(contract_)
            self.create_transaction(pub, 'f1f91c30722f64de1c004423c091ce33', gas_price, priv, contract_)
            return wallet  


    def _validate_transaction(self, from_, to, amount, private_key):

        # Check that values actually exist
        if not from_ or not to or not amount or not private_key:
            return False

        # Check that addresses exist and are not the same
        if from_ not in self.wallets.keys() \
                or to not in self.wallets.keys() \
                or from_ == to:
            return False

        # Check that transaction generator is owner
        if not private_key == self.wallets[from_]['private_key']:
            return False

        # Check that amount is float or int
        try:
            amount = float(amount)
        except ValueError:
            return False

        # Check amount is valid and spendable
        if not amount > 0 \
                or not amount <= self.wallets[from_]['balance']:
            return False

        return True

    def _choose_transactions_from_mempool(self, block_num):
        processed_transactions = {}
        contract_states = {}
        while len(processed_transactions) < 10 and len(self.mempool) > 0:
            transaction_id = random.choice(list(self.mempool))
            transaction = copy.deepcopy(self.mempool[transaction_id])
            if type(transaction['message']) is dict:
                prev_block = self.chain[block_num -1]
                contract_code = self.wallets[transaction['to']]['contract_code']
                contract_state = prev_block['contract_states']
                try:
                    state = contract_state[self.wallets[transaction['to']]]
                except:
                    state = 0
                sys.argv = [state]
                contract_states[transaction['to']] = \
                        exec(self.wallets[transaction['to']]['contract_code'])
                transaction['to'] = 'f1f91c30722f64de1c004423c091ce33'
            if transaction['amount'] <= self.wallets[transaction['from']]['balance']:
                self.wallets[transaction['from']]['balance'] -= transaction['amount']
                self.wallets[transaction['to']]['balance'] += transaction['amount']
                processed_transactions[transaction_id] = transaction
            del sys.argv
            del self.mempool[transaction_id]
        return processed_transactions, contract_states

    def _calculate_merkle_root(self, transactions):

        if len(transactions) == 0:
            return None

        if len(transactions) == 1:
            return transactions[0]

        new_transactions = []

        for i in range(0, len(transactions), 2):

            if len(transactions) > (i+1):
                new_transactions.append(
                    self._hash_data(transactions[i] + transactions[i+1])
                )
            else:
                new_transactions.append(transactions[i])

        return self._calculate_merkle_root(new_transactions)

    def _calculate_state_merkle_root(self, contracts):
        
        if len(contracts) == 0:
            return None

        if len(contracts) == 1:
            return contracts[0]

        new_contracts = []

        for i in range(0, len(contracts), 2):

            if len(contracts) > (i+1):
                new_contracts.append(
                    self._hash_data(contracts[i] + contracts[i+1])
                )
            else:
                new_contracts.append(contracts[i])

        return self._calculate_state_merkle_root(new_contracts)    

    def _check_merkle_root(self, block):
        return self._calculate_merkle_root(list(block['transactions'])) \
            == block['header']['merkle_root']

    def _calculate_gas(self, message):
        gas_price = sys.getsizeof(message) * 0.001
        return gas_price
###############################################################################

    @property
    def length(self):
        return len(self.chain)

    def add(self):
        block = self._create_block()
        return self._mine_block(block)

    def check(self):

        results = []

        for block in reversed(self.chain):

            block_number = block['header']['number']

            if not block['hash'] == self._hash_data(block['header']):
                results.append(f'block-{block_number}: invalid hash')

            if block_number > 0:

                previous_block = self.chain[block_number - 1]

                if not block['header']['previous_block'] == previous_block['hash']:
                    results.append(f'block-{block_number}: invalid block pointer')

            if not self._check_merkle_root(block):
                results.append(f'block-{block_number}: invalid merkle root')

        return "ok" if not results else results

    def _create_block(self):
        self.state = self.state + 1
        return {
            'header': {
                'number': len(self.chain),
                'time': datetime.datetime.utcnow().timestamp(),
                'nonce': None,
                'previous_block': self._get_last_block_hash(),
                'merkle_root': None,
                'statemerkle': None,
            },
            'transactions': {},
            'contract_states': {self.state},
            'hash': None
        }
    def _get_last_block_hash(self):
        return self.chain[-1]['hash'] if len(self.chain) > 0 else None
    
    def _mine_block(self, block):
        block['transactions'], block['contract_states'] = self._choose_transactions_from_mempool(block['header']['number'])
        block['header']['merkle_root'] = \
            self._calculate_merkle_root(list(block['transactions']))
        #print(list(block['contract_states']))
        block['header']['statemerkle'] = \
            self._calculate_state_merkle_root(list(block['contract_states']))
        #print(block['header']['statemerkle'])
        print("block['header']['statemerkle']: ", block['header']['statemerkle'])
        while True:
            block['header']['nonce'] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')
            block['hash'] = self._hash_data(block['header'])
            if block['hash'][:self.difficulty] == '0' * self.difficulty:
                break
        self.chain.append(block)
        return block

    def _hash_data(self, data):

        hashId = hashlib.sha256()

        if isinstance(data, dict):
            hashId.update(repr(data).encode('utf-8'))
            return self._hash_data(str(hashId.hexdigest()))
        else:
            hashId.update(data.encode('utf-8'))
            return str(hashId.hexdigest())


# ------------------------------ FLASK ROUTES ------------------------------- #

@app.route('/api/blockchain', methods=['GET'])
def get_blockchain_info():
    return Response(
        response=json.dumps({
            'length': blockchain.length,
            'difficulty': blockchain.difficulty,
            'validity': blockchain.check(),
        }),
        status=200,
        mimetype='application/json'
    )
@app.route('/api/blockchain/block/<int:number>', methods=['GET'])
def get_block(number):
    return Response(
        response=json.dumps(
            blockchain.chain[number] if number < len(blockchain.chain) else None
        ),
        status=200,       mimetype='application/json'
    )
@app.route('/api/blockchain/block', methods=['GET'])
def get_all_blocks():
    return Response(
        response=json.dumps(blockchain.chain),
        status=200,
        mimetype='application/json'
    )
@app.route('/api/blockchain/block', methods=['POST'])
def add_block():
    return Response(
        response=json.dumps(blockchain.add()),
        status=200,
        mimetype='application/json'
    )

ALLOWED_EXTENSIONS = {'.py', '.txt'}

def allowed_file(filename):
    foo = '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    if foo == False:
        return "False"
    else:
        return "True"
@app.route('/api/blockchain/wallet', methods=['GET', 'POST'])
def add_wallet():
    if request.method == 'GET':
        return render_template('addwallet.html')
    elif request.method == 'POST':
        if 'file' not in request.files:
            return Response(
                    response=json.dumps(blockchain.create_wallet()),
                    status=200,
                    mimetype='application/json'
                    )
        else:
            file_ = request.files['file']
            priv_key = request.form['priv_key']
            pub_key = request.form['pub_key']
            if file_.filename == '':
                return Response(
                        response=json.dumps(blockchain.create_wallet()),
                        status=200,
                        mimetype='application/json'
                        )
            elif file_ and allowed_file(file_.filename):
                return Response(
                        response=json.dumps(blockchain.create_wallet(contract_=file_.read(), priv=priv_key, pub=pub_key)),
                        status=200,
                        mimetype='application/json'
                        )
@app.route('/api/blockchain/balances', methods=['GET'])
def get_wallet_balances():
    return Response(
        response=json.dumps(
            {key: blockchain.wallets[key]['balance']
             for key in blockchain.wallets.keys()}
        ),
        status=200,
        mimetype='application/json'
    )
@app.route('/api/blockchain/transaction', methods=['POST'])
def add_transaction():
    if not all(k in request.form for k in ['from', 'to', 'amount', 'private_key']):
        return Response(
            response=json.dumps({'error': 'missing required parameter(s)'}),
            status=400,
            mimetype='application/json'
        )

    return Response(
        response=json.dumps(
            blockchain.create_transaction(
                request.form['from'],
                request.form['to'],
                request.form['amount'],
                request.form['private_key']
            )
        ),
        status=200,
        mimetype='application/json'
    )
@app.route('/api/blockchain/mempool', methods=['GET'])
def get_mempool():
    return Response(
        response=json.dumps(blockchain.mempool),
        status=200,
        mimetype='application/json'
    )
if __name__ == '__main__':
    blockchain = Blockchain()
    app.run(host='127.0.0.1', port=8080, debug=1)
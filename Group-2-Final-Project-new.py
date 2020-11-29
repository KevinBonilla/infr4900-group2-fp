#!/usr/bin/env python

import os
import binascii
import datetime
import hashlib
import random
import copy
import ast

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
        self.memconpool = {}
        self.contracts = {}
        self.add()

###################### ADD CODE ONLY BETWEEN THESE LINES! #####################
    
    #TODO: HARDCODE A WALLET(ADDRESS) THAT WILL BE USED TO TRANSFER/DEDUCT FUNDS FOR THE UPLOADING OF CONTRACT


    def create_wallet(self, contract_):
        if contract_==None:
            wallet = {
                'public_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'private_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'balance': 10.0,
            }
            self.wallets[wallet['public_key']] = wallet
            return wallet

        elif contract_ is not None:
            contract = {
                'public_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
                'contract_code': contract_,
            }
            self.contracts[contract['public_key']] = contract
            return contract


    #TODO: CREATE A TRANSACTION HERE THAT SUBTRACTS FROM CONTRACT UPLOADERS BALANCE
    #TODO: I NEED A GAS CALCULATION FUNCTION TO BE CALLED HERE TO GET THE COST FOR UPLOAD
    def create_contract(self, from_, to, amount, message, startgas, public_key):
        if not self._validate_contract(from_, to, amount, message, startgas, public_key):
            return {'error: invalid contract definition'}

            contract = {
                'time': datetime.datetime.utcnow().timestamp(),
                'from': from_,
                'to': to,
                'amount': amount,
                'message': string(message),
                'startgas': startgas,
                'gasprice': gasprice._calculate_gas(message, startgas), #TODO Need to calculate gas by message and startgas
            }

            contract_id = self._hash_data(contract_id)
            self.memconpool[contract_id] = contract

            return{contract_id: contract}

    def _validate_contract(self, from_, to, amount, message, startgas, public_key):

        # Check that values actually exist
        if not from_ or not to or not amount or not message or not startgas or not public_key:
            return False

        # Check that addresses exist and are not the same
        if from_ not in self.wallets.keys() \
                or to not in self.wallets.keys() \
                or from_ == to:
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
    def create_transaction(self, from_, to, amount, private_key):

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

    def _choose_transactions_from_mempool(self):

        processed_transactions = {}

        while len(processed_transactions) < 10 and len(self.mempool) > 0:

            transaction_id = random.choice(list(self.mempool))
            transaction = copy.deepcopy(self.mempool[transaction_id])

            if transaction['amount'] <= self.wallets[transaction['from']]['balance']:

                self.wallets[transaction['from']]['balance'] -= transaction['amount']
                self.wallets[transaction['to']]['balance'] += transaction['amount']

                processed_transactions[transaction_id] = transaction

            del self.mempool[transaction_id]

        return processed_transactions

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

    def _check_merkle_root(self, block):
        return self._calculate_merkle_root(list(block['transactions'])) \
            == block['header']['merkle_root']


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
        return {
            'header': {
                'number': len(self.chain),
                'time': datetime.datetime.utcnow().timestamp(),
                'nonce': None,
                'previous_block': self._get_last_block_hash(),
                'merkle_root': None,
            },
            'transactions': {},
            'hash': None
        }

    def _get_last_block_hash(self):
        return self.chain[-1]['hash'] if len(self.chain) > 0 else None

    def _mine_block(self, block):

        block['transactions'] = self._choose_transactions_from_mempool()
        block['header']['merkle_root'] = \
            self._calculate_merkle_root(list(block['transactions']))
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
     
    def _calculate_gas(self, message, startgas):            
        if not message or not startgas:
            raise Exception("Invalid data")
        gas = len(message) * 0.001
        try:
            float(startgas)
        except ValueError:
            raise Exception("Invalid value")              
        if not float(gas) > 0:
            raise Exception("Invalid data")
        if not float(gas) <= startgas:
            raise Exception("Invalid data")
        total_gas = startgas - gas
        return total_gas
 
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
        status=200,
        mimetype='application/json'
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


''' I HAVE MODIFIED THIS SO THAT, FIRSTLY, IT SHOWS A WEBPAGE THAT ALLOWS THE USER TO UPLOAD A CONTRACT IN 
THE FORM OF A .py FILE.  IF THE USER DOES NOT UPLOAD ANYTHING, IT IS ASSUMED THAT THE USER IS JUST CREATING
A REGULAR WALLET FOR FUNDS.  ONCE THE FORM IS SUBMITTED ON THE addwallet.html FORM, IT IS PASSED TO THE 
create_wallet() FUNCTION WHERE THE CONTRACT CAN BE PUBLISHED IN A TRANSACTION AND FUNDS SUBTRACTED FROM THE
UPLOADER'S WALLET.  AGAIN, IF NO .py FILE IS UPLOADED, ONLY A REGULAR WALLET IS CREATED.  SEE THE create_wallet()
FUNCTION ABOVE FOR MORE DETAILS.'''

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
            if file_.filename == '':
                contract_dict = None
                return Response(
                        response=json.dumps(blockchain.create_wallet(contract_=None)),
                        status=200,
                        mimetype='application/json'
                        )
            elif file_ and allowed_file(file_.filename):
                contractContent = file_.read()
                return Response(
                        response=json.dumps(blockchain.create_wallet(contract_=contractContent)),
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

@app.route('/api/blockchain/contract', methods=['POST'])
def add_contract():

    if not all(k in request.form for k in ['from', 'to', 'amount', 'public_key', 'startgas']):
        return Response(
            response=json.dumps({'error': 'missing required parameter(s)'}),
            status=400,
            mimetype='application/json'
        )

    return Response(
        response=json.dumps(
            blockchain.create_contract(
                request.form['from'],
                request.form['to'],
                request.form['amount'],
                request.form['public_key'],
                request.form['startgas'],
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

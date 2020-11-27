#!/usr/bin/env python

# Kevin Bonilla - 100551700
# Kevin Yardy - 
# Nazmul Hassan Rasel - 100796771
# Christian Fuller - 
import os
import binascii
import datetime
import hashlib
import random
import copy

from flask import Flask, request, json, Response

app = Flask(__name__)


# ----------------------- BLOCKCHAIN CLASS ---------------------------------- #

class Blockchain:

    def __init__(self):

        self.chain = []
        self.difficulty = 3
        self.wallets = {}
        self.mempool = {}
        self.add()

###################### ADD CODE ONLY BETWEEN THESE LINES! #####################

    def create_wallet(self):

        wallet = {
            'public_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
            #'private_key': binascii.b2a_hex(os.urandom(16)).decode('utf-8'),
            'balance': 10.0,
        }

        self.wallets[wallet['public_key']] = wallet
        return wallet

    def create_transaction(self, cid, from_, to, amount, message, startgas, gasprice):

        if not self._validate_transaction(from_, to, amount, message):
            return {'error': 'invalid transaction'}

        transaction = {
            'time': datetime.datetime.utcnow().timestamp(),
            'contract_id': cid,
            'from': from_,
            'to': to,
            'amount': float(amount),
            'message': message,
            'startgas': float(startgas),
            'gasprice': float(gasprice)
        }


        transaction_id = self._hash_data(transaction)
        self.mempool[transaction_id] = transaction

        return {transaction_id: transaction}

    def _validate_transaction(self, from_, to, amount, message):

        # Check that values actually exist
        if not from_ or not to or not amount:
            return False

        # Check if message field is empty, do transaction
        if not message:
        	return True

        # Check if message pub key addr exists
        if message not in self.wallet.values():
        	return False

        # Check that addresses exist and are not the same
        if from_ not in self.wallets.keys() \
                or to not in self.wallets.keys() \
                or from_ == to:
            return False

        # Check that transaction generator is owner
        #if not private_key == self.wallets[from_]['private_key']:
        #    return False

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
        
    #Calculate gas from the transaction message
    def client_message(self, From, To, gas_amount, Private):            
        
        try:
            transaction_message = {
                'Time': datetime.datetime.utcnow().timestamp(),
                'From': From,
                'To': To,
                'gas': gas_amount
            }
         except:
            return False
            
            private_key = Private
            if(not (From and From.strip())): 
                return False
            if(not (To and To.strip())): 
                return False
            if(not (private_key and private_key.strip())): 
                return False
            try:
                float(gas_amount)
            except ValueError:
                return False
            if From == To:
                return False  
            if not transaction_messages['To'] in self.wallets:
                return False
            if not transaction_messages['From'] in self.wallets:
                return False
            if not private_key == self.wallets[transaction_message['From']]['private_key']:
                return False                       
            if not float(gas_amount) > 0:
                return False 
            if not float(gas_amount) <= self.wallets[transaction_message['From']]['balance']:
                return False
            return True

        hashed_transaction_message = self.hash_transaction(transaction_message)
        self.transaction_messages[hashed_transaction_message] = transaction_message

        return hashed_transaction_message
    
    #Removed old transaction message from the chain
    def removed_transaction_from_transaction_message(self):

        executed_transaction = {}

        while len(self.transaction_messages) > 0:
            transaction_id = list(self.transaction_messages)[len(self.transaction_messages) - 1]
            transaction = copy.deepcopy(self.transaction_messages[transaction_id])

            if transaction['gas'] <= self.wallets[transaction['From']]['balance']:

                deducted_balance = self.wallets[transaction['From']]['balance'] - transaction['gas']

                executed_transaction[transaction_id] = transaction
            
            del self.transaction_messages[transaction_id]

        return executed_transaction
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


@app.route('/api/blockchain/wallet', methods=['POST'])
def add_wallet():
    return Response(
        response=json.dumps(blockchain.create_wallet()),
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

    if not all(k in request.form for k in ['from', 'to', 'amount', 'message']):
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
                request.form['message']
                #request.form['private_key']
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

#Transaction message sending from HTML for GAS
@app.route('/client_message', methods = ['POST'])
def client_message():

    From = request.form['From']
    To = request.form['To']
    ClientMessage = request.form['Message']
    Private = request.form['private']
    gas_amount = len(ClientMessage) * 1.0
    hashed_transaction_message = blockchain.send_message(From, To, gas_amount, Private)

    if not hashed_transaction_message:
        return Response(json.dumps({'Error': 'Please input a valid message.'}), status=400, mimetype='application/json')

    else:
        return Response(json.dumps({'Result': hashed_transaction_message}), status=200, mimetype='application/json')

#Redirect application to the root page
@app.route('/', methods=['GET'])
def get_index():
    return render_template('index.html')


if __name__ == '__main__':
    blockchain = Blockchain()
    app.run(host='127.0.0.1', port=8080, debug=1)

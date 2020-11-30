How to run 

1. First run the program by `python3 Group-2-Final-Project.py`

2. Visit the landing page via `http://localhost:8080/api/blockchain/wallet`

3. If the user wants to generate a wallet, leave all fields blank and hit `submit`. There a wallet should be generated.

Example Output: {"balance": 10.0, "private_key": "2fdad24cd8f8a26c8b8dabb128db98d2", "public_key": "740ba58fe5197879f98b61bf02977d61"}

4. Now if you want to upload a contract, the user must upload a .py or .txt file. An example python file we used was this

def incrementor(a):
	a = a + 1
	return(a)
	
if __name__ == '__main__':
	incrementor(sys.argv[0])
	
5. Now to upload the contract in `http://localhost:8080/api/blockchain/wallet` enter your wallets private key and the contract public key. Since
we generate a genesis block at execution the first "Contract Public Key" will be `f1f91c30722f64de1c004423c091ce33` and in this example "Your Private
Key" will be `740ba58fe5197879f98b61bf02977d61`

You should see the contract output look like so 
{"contract_code": "def incrementor(a):\r\n\ta = a + 1\r\n\treturn(a)\r\n\t\r\nif __name__ == '__main__':\r\n\tincrementor(sys.argv[0])", "public_key": "816edb1ff6493710cfaea7c262971e43"}


6. Now to call the transaction the user must interact with the /api/blockchain/transaction route. 
```
Where from = User public key 
to = contract_code public key
amount = irrelevant value(set as 1)
private_key = User private key
```
In our example, the POST would look like this: 
`curl -X POST --data 'from=740ba58fe5197879f98b61bf02977d61&to=816edb1ff6493710cfaea7c262971e43&amount=1&private_key=2fdad24cd8f8a26c8b8dabb128db98d2' localhost:8080/api/blockchain/transaction`


7. Now that the transaction is pushed we need to mine the blocks, run a curl -X POST localhost:8080/api/blockchain/block

8. To view the blocks, either run a GET or visit this path localhost:8080/api/blockchain/block/<int>


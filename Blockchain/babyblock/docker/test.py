from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

w3 = Web3(HTTPProvider('http://localhost:8545'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

abi = """
[
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"constant": false,
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_num",
				"type": "uint256"
			}
		],
		"name": "guessNumber",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "isSolved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "solved",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
"""

privatekey = 0x25ece0fd60eb70e6216623edf3a6f11f38f690cac80a4d7a35f4c60648e25043
acct = w3.eth.account.from_key(privatekey)
address = w3.eth.account.from_key(privatekey).address
# print(address)

#获取余额
# address = "0x1F933E837C02eE03497129e7C378b0BB9D502809"
contractaddr = "0x44e406030B4A55DF1db1De7dE01dfe3b1a05d908"

contract = w3.eth.contract(address=contractaddr, abi=abi)

guessed_number = w3.eth.get_block('latest')['timestamp'] % 10 + 1

# 如果block.timestamp的LSB不同于guessedNumber，那么加1
if (w3.eth.get_block('latest')['timestamp'] & 1) != (guessed_number & 1):
    guessed_number += 1

contract_txn = contract.functions.guessNumber(guessed_number).build_transaction({
    'from': address,
    'nonce': w3.eth.get_transaction_count(address),
    'gas': 1000000,
    'gasPrice': w3.to_wei('1', 'gwei')
})

signed_txn = acct.sign_transaction(contract_txn)
txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
print(txn_receipt)

print(contract.functions.isSolved().call())
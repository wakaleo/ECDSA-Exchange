const express = require('express');
const EC = require('elliptic').ec;
const SHA256 = require('crypto-js/sha256');
const app = express();
const cors = require('cors');
const port = 3042;

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

const ec = new EC('secp256k1');

let accounts = new Map()
for(let i = 0; i < 3; i++) {
  const account = ec.genKeyPair();
  const publicKey = account.getPublic().encode('hex');
  const privateKey = account.getPrivate().toString(16);
  const accountNumber = publicKey.slice(90);
  accounts.set(accountNumber, {
    number: accountNumber,
    publicKey: publicKey,
    balance: 100 + i * 50,
    privateKey: privateKey,
  });
}
console.log("Available Accounts")
console.log("------------------")
for (let account of accounts.values()){
	console.log(`${account.number}: ${account.balance} ETH`);
	console.log(`  - Public key: ${account.publicKey}`);
}

console.log("");
console.log("Private Keys")
console.log("------------------")
for (let account of accounts.values()){
	console.log(`${account.number}: ${account.privateKey}`);
}


app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  console.log("Looing up balance of address " + address)
  const account = accounts.get(address)
  const balance = account.balance || 0;
  res.send({ balance });
});

app.post('/send', (req, res) => {
  const {sender, recipient, amount, privateKey} = req.body;

  const senderAccount = accounts.get(sender)
  const recipientAccount = accounts.get(recipient)

  const ecPrivateKey = ec.keyFromPrivate(privateKey);
  const transaction = {sender: sender, recipient: recipient, amount: amount}
  console.log("Transaction: " + JSON.stringify(transaction))

  // Create a transaction message including a hash of the transaction
  const transationHash = SHA256(JSON.stringify(transaction)).toString();
  console.log("Transaction hash: " + transationHash)

  // Sign the transaction with provided the private key
  const signature = ecPrivateKey.sign(transationHash);
  console.log("Signature: " + JSON.stringify(signature))

  // Verify the transaction using the public key of the sender account
  const publicKey = senderAccount.publicKey
  console.log("Verifying with public key: " + JSON.stringify(publicKey))
  
  const ecPublicKey = ec.keyFromPublic(publicKey, 'hex');

  const transactionVerified = ecPublicKey.verify(transationHash, signature);
  if (transactionVerified) {
    senderAccount.balance -= amount;
    recipientAccount.balance = (recipientAccount.balance || 0) + +amount;
    res.send({ balance: senderAccount.balance });
  } else {
    console.log("Unauthorised transaction")
    res.status(400);
    res.send('Unauthorised transaction');
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

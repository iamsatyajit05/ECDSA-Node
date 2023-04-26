const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;

const secp = require("ethereum-cryptography/secp256k1");
const { toHex, utf8ToBytes } = require("ethereum-cryptography/utils");
const { keccak256 } = require("ethereum-cryptography/keccak");

app.use(cors());
app.use(express.json());

const balances = {
  // 0b8b820b061d684611de5b28a2c64bad6477aaa66bc7bec4811e13ab2aab6609
  "04a1df85dcfd39c608e1e499ed47514190a54cbe46d9402ceaa6770b42dba95cc0d4b8703af4fe2e368636a7c2037b2360c6e92fbc75541af7e28c0bfc9bab4d2b": 90,
  // 7b8f48aa42064063743b03be22221beaaf3e394a58c77e09453d6795b3365452
  "041a9d0fa5b31d02daf2cef19bcf65ed877eb6673ed288d748aa028e99f32d92f4a9555570791898f3e97ad7a35c18652de4b3eb37090ec360be5db13d75458e3c": 50,
  // cb90c9c165c77cac33d4965625f234801f2fef93dce54d0e6db6077e218784ab
  "048e483baa48b3eb929717d8d7067f256b6d2464a857b0d4e06278c0ad2bf707f9448d3b718b92b86650d0c26e01d60bf09e811cff7ae64ec72f6e0ba9b7ba4536": 75,
};

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  // TODO: get a signature from the client-side applications
  // recover the public address from the signature

  // Incorporate Public Key Cryptography so transfers can only be completed with a valid signature
  // The person sending the transaction should have to verify that they own the private key corresponding to the address that is sending funds

  const { sender, recipient, amount, signTransaction, message } = req.body;

  setInitialBalance(sender);
  setInitialBalance(recipient);

  const [signature, recoveryBit] = signTransaction;
  
  const formattedSignature = Uint8Array.from(Object.values(signature));
  
  const msgToBytes = utf8ToBytes(message);
  const msgHash = toHex(keccak256(msgToBytes));

  const publicKey = secp.recoverPublicKey(msgHash, formattedSignature, recoveryBit);

  const isValid = secp.verify(formattedSignature, msgHash, publicKey)

  // console.log("Is valid? ", isValid);

  if (isValid) {
    if (balances[sender] < amount) {
      res.status(400).send({ message: "Not enough funds!" });
    } else {
      balances[sender] -= amount;
      balances[recipient] += amount;
      res.send({ balance: balances[sender] });
    }
  }
  else {
    res.status(400).send({ message: "Something Wrong!" });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
const secp = require("ethereum-cryptography/secp256k1");
const { toHex } = require("ethereum-cryptography/utils");

const privateKey = secp.utils.randomPrivateKey();
const publicKey = secp.getPublicKey(privateKey);

console.log("Private Key: ", toHex(privateKey));
console.log("Public Key: ", toHex(publicKey));
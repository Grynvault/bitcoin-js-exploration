/** @format */

import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import * as tools from 'uint8array-tools';
import dotenv from 'dotenv';
import bip65 from 'bip65';

dotenv.config();

const network = bitcoin.networks.bitcoin; // Mainnet
const ECPair = ECPairFactory(ecc);

const alicBufferedPrivateKey = process.env.ALICE_BUFFERED_PRIVATE_KEY;
const allicePrivatekey = Buffer.from(alicBufferedPrivateKey.toString('hex'), 'hex');

const bobBufferedPrivateKey = process.env.BOB_BUFFERED_PRIVATE_KEY;
const bobPrivatekey = Buffer.from(bobBufferedPrivateKey.toString('hex'), 'hex');

//Using the private key to create a keypair
const alice = ECPair.fromPrivateKey(allicePrivatekey);
const bob = ECPair.fromPrivateKey(bobPrivatekey);

const hashType = bitcoin.Transaction.SIGHASH_ALL;

/**
 * 
✅ Spending Path 1: Wait for Timeout (CLTV)
1️⃣ The transaction includes lockTime.
2️⃣ OP_CHECKLOCKTIMEVERIFY prevents spending before lockTime is reached.
3️⃣ Once the timeout expires, only aQ.publicKey needs to sign.

✅ Spending Path 2: Immediate Spend by bQ.publicKey
1️⃣ If bQ.publicKey signs immediately, OP_ELSE executes.
2️⃣ OP_CHECKSIGVERIFY ensures bQ provides a valid signature.
3️⃣ Then, aQ.publicKey must also sign to spend the funds.
 */
function cltvCheckSigOutput(
	aQ, //Alice's public key
	bQ, //Bob's public key
	lockTime,
) {
	return bitcoin.script.fromASM(
		`
        OP_IF
            ${tools.toHex(bitcoin.script.number.encode(lockTime))}
            OP_CHECKLOCKTIMEVERIFY
            OP_DROP
        OP_ELSE
            ${tools.toHex(bQ.publicKey)}
            OP_CHECKSIGVERIFY
        OP_ENDIF
        ${tools.toHex(aQ.publicKey)}
        OP_CHECKSIG
      `
			.trim()
			.replace(/\s+/g, ' '),
	);
}

function utcNow() {
	return Math.floor(Date.now() / 1000);
}

//~ Mon, Mar 3 4:09PM
// const lockTime = bip65.encode({ utc: 1740989341 });

//Lock time an hour from now
const lockTime = bip65.encode({ utc: utcNow() + 3600 });
const redeemScript = cltvCheckSigOutput(alice, bob, lockTime);

//Keep a copy of the lockTime
console.log('lockTime', lockTime);
console.log('redeemScript -> ', redeemScript);

const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
	},
});

//Fund this address, and copy the transaction id (UTXO)
console.log('address ->', address);

//transaction id: 50edc9008afc83fbdac90783bec17daaebcb837883018476833af77bc5b41ff6
//Balance: 0.00001 BTC = 1,000 sats
//Amount: 0.000007, gas fees: 0.000003
//Replace this UTXO with your own
const utxo = {
	txid: '50edc9008afc83fbdac90783bec17daaebcb837883018476833af77bc5b41ff6',
	vout: 0,
};

const tx = new bitcoin.Transaction();
tx.locktime = lockTime;
tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, 0xfffffffe);

/**
 *
 *
 * ✅ Spending Path 1: Wait for Timeout (CLTV)
 *
 * **/

const recipientAddress = 'bc1qyhrr4gelwscr57tud95urckngzvhymc58tdhjh'; //Alice's p2wpkh address
const amount = 700;
const scriptPubkey = bitcoin.address.toOutputScript(recipientAddress, network);

tx.addOutput(scriptPubkey, amount);

// Alice's signature
const signatureHash = tx.hashForSignature(0, redeemScript, hashType);
const redeemScriptSig = bitcoin.payments.p2sh({
	redeem: {
		input: bitcoin.script.compile([bitcoin.script.signature.encode(alice.sign(signatureHash), hashType), bitcoin.opcodes.OP_TRUE]),
		output: redeemScript,
	},
}).input;

// Ensure `redeemScriptSig` is not undefined before setting it
if (redeemScriptSig) {
	tx.setInputScript(0, redeemScriptSig);
	console.log('redeemScriptSig ->', redeemScriptSig);
} else {
	console.error('Error: redeemScriptSig is undefined');
}

console.log('To be broadcast =>', tx.toHex());

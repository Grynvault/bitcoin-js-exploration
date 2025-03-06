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

//~ Mon, Mar 5 12:04PM
//Lock time an hour from now
const lockTime = bip65.encode({ utc: 1741147455 });
// const lockTime = bip65.encode({ utc: utcNow() + 3600 });
const redeemScript = cltvCheckSigOutput(alice, bob, lockTime);

//Keep a copy of the lockTime
// console.log('lockTime', lockTime);
// console.log('redeemScript -> ', redeemScript);

const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
	},
});

//Fund this address, and copy the transaction id (UTXO)
// console.log('address ->', address);

/**
 *
 * Adress: 3QZdLMbL7cNPB444PcX9hsX5NM7x7rbWZG
 * Transaction id (UTXO): 6a3abec4a70beb0f0c9d8380354e62424aee08d5b299eb5462af431ff4a68803
 * Balance: 0.00002000 BTC -> 2,000 Satoshis
 * Amount to spend: 1,000 Satoshis
 * Gas fees: 1,000 Satoshis
 *
 */

//Replace this UTXO with your own
const utxo = {
	txid: '6a3abec4a70beb0f0c9d8380354e62424aee08d5b299eb5462af431ff4a68803',
	vout: 0,
};

const tx = new bitcoin.Transaction();
tx.locktime = lockTime;
tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, 0xfffffffe);

const recipientAddress = 'bc1qyhrr4gelwscr57tud95urckngzvhymc58tdhjh'; //Alice's p2wpkh address
const amount = 1000;
const scriptPubkey = bitcoin.address.toOutputScript(recipientAddress, network);

tx.addOutput(scriptPubkey, amount);

// Alice's signature
const signatureHash = tx.hashForSignature(0, redeemScript, hashType);

/**
 *
 *
 * ✅ Spending Path 1: Wait for Timeout (CLTV)
 *
 * **/
const redeemScriptSig = bitcoin.payments.p2sh({
	redeem: {
		input: bitcoin.script.compile([bitcoin.script.signature.encode(alice.sign(signatureHash), hashType), bitcoin.opcodes.OP_TRUE]),
		output: redeemScript,
	},
}).input;

/**
 *
 *
 * ✅ Script Path 2: Immediate Spend with Bob's signature
 *
 * **/
// const redeemScriptSig = bitcoin.payments.p2sh({
// 	redeem: {
// 		input: bitcoin.script.compile([
// 			bitcoin.script.signature.encode(alice.sign(signatureHash), hashType),
// 			bitcoin.script.signature.encode(bob.sign(signatureHash), hashType),
// 			bitcoin.opcodes.OP_FALSE,
// 		]),
// 		output: redeemScript,
// 	},
// }).input;

// Ensure `redeemScriptSig` is not undefined before setting it
if (redeemScriptSig) {
	tx.setInputScript(0, redeemScriptSig);
} else {
	console.error('Error: redeemScriptSig is undefined');
}

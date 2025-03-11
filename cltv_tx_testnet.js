/** @format */

import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import * as tools from 'uint8array-tools';
import dotenv from 'dotenv';
import bip65 from 'bip65';

dotenv.config();

const TESTNET = bitcoin.networks.testnet; // Testnet
// console.log('TESTNET', TESTNET);
const ECPair = ECPairFactory(ecc);

const aliceBufferedPrivateKey = process.env.TESTNET_ALICE_BUFFERED_PRIVATE_KEY;
const allicePrivatekey = Buffer.from(aliceBufferedPrivateKey.toString('hex'), 'hex');

const bobBufferedPrivateKey = process.env.TESTNET_BOB_BUFFERED_PRIVATE_KEY;
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

//Lock time half an hour from now
// const lockTime = bip65.encode({ utc: utcNow() + 1800 });
const lockTime = bip65.encode({ utc: 1741327649 });
const redeemScript = cltvCheckSigOutput(alice, bob, lockTime);

//Keep a copy of the lockTime
console.log('Save the lockTime', lockTime);

const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
		network: TESTNET,
	},
	network: TESTNET,
});

//Fund this address, and copy the transaction id (UTXO)
console.log('address ->', address);

/***
 * 
 *  Script Address: 2N6aSvZ9NSVnCXRRsPxazk1oSvECe2tnVo8
 * 
 * 
 * MAKE SURE TO COMMENT OUT THE REST OF THE CODE BELOW UNTIL YOU GET THE UTXO
 * THEN FILL THE INFORMATION BELOW
 * 
 * 
 * Recent Block Timestamp: 2025-03-07 12:06:08
 * 
 * Locktime in UNIX Timestamp: 1741327649
 * In UTC Time: Fri Mar 07 2025 14:07:29 GMT+0800 (Malaysia Time)
 * 
 * Transaction Id (UTXO): c81daa56d6fdf899cecb67ef540679a1cc13071ce45735060b7344cb98354a08
 * Balance: 0.00005 tBtc = 5,000 sats
 * Amount to be redeemed: 4,000 sats
 * Gas fees: 1,000 sats
 * 
 * /



/**
 *
 *
✅ Spending Path 2: Immediate Spend by bQ.publicKey
 *
 * **/
//Replace this UTXO with your own
const utxo = {
	txid: '1f2933553e84372e7c1559c289befebcb1b7157dcf15b884b67d38ffc200ad80',
	vout: 0,
};
const recipientAddress = 'tb1qmdyklysj3syrs9zsvrekrrd6smgpvc2lm6mpt4'; //Alice's p2wpkh address
const amount = 4500;
const scriptPubkey = bitcoin.address.toOutputScript(recipientAddress, TESTNET);

const tx = new bitcoin.Transaction(TESTNET);
// tx.locktime = lockTime;
tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, 0xfffffffe);
tx.addOutput(scriptPubkey, amount);

// {Alice's signature} {Bob's signature} OP_FALSE
const signatureHash = tx.hashForSignature(0, redeemScript, hashType);
// console.log('signatureHash ->', signatureHash);

//Redeem Script Path 1: Wait for Timeout
// const redeemScriptSig = bitcoin.payments.p2sh({
// 	redeem: {
// 		input: bitcoin.script.compile([bitcoin.script.signature.encode(alice.sign(signatureHash), hashType), bitcoin.opcodes.OP_TRUE]),
// 		output: redeemScript,
// 	},
// }).input;

//Redeem Script Path 2: Immediate Spend with Bob's signature
const redeemScriptSig = bitcoin.payments.p2sh({
	redeem: {
		input: bitcoin.script.compile([
			bitcoin.script.signature.encode(alice.sign(signatureHash), hashType),
			bitcoin.script.signature.encode(bob.sign(signatureHash), hashType),
			bitcoin.opcodes.OP_FALSE,
		]),
		output: redeemScript,
	},
}).input;

if (redeemScriptSig) {
	tx.setInputScript(0, redeemScriptSig);
	console.log('redeemScriptSig ->', redeemScriptSig);
} else {
	console.error('Error: redeemScriptSig is undefined');
}

console.log('To be broadcast =>', tx.toHex());

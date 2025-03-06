/** @format */

import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import * as tools from 'uint8array-tools';
import dotenv from 'dotenv';
import bip65 from 'bip65';

dotenv.config();

const TESTNET = bitcoin.networks.testnet; // Testnet
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
 * Notes on OPCODES
 * 
 * 1. OP_CHECKSIG (0xac)
    What It Does
   - Verifies that a provided digital signature matches the public key and the transaction data.
   - If the verification is successful, it pushes 1 (true) onto the stack.
   - If the verification fails, it pushes 0 (false) onto the stack.

  2. OP_CHECKSIGVERIFY (0xad)
    What It Does
   - Works exactly like OP_CHECKSIG, but it does not leave a 1 or 0 on the stack.
   - If the signature verification fails, it immediately stops script execution with an error.
   - If it succeeds, the script continues without modifying the stack.
 * 
 */

function opIfScriptPub(aQ, bQ) {
	return bitcoin.script.fromASM(
		`
            OP_IF
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

const redeemScript = opIfScriptPub(alice, bob);
const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
		network: TESTNET,
	},
	network: TESTNET,
});

console.log('address ->', address);

/**
 *
 * Script Adress: 2NFdCHakWV6DqcVNgDZDroLNSfaJb7cBkdR
 *
 * Transaction ID (UTXO): 8d23fb69c2941a3f0189aa145db1a0105a232a30b3400551632060f43ad49f88
 * Balance: 0.00001000 BTC -> 1,000 Satoshis
 * Amount: 800 Satoshis
 * Gas fees: 200 Satoshis
 */

const utxo = {
	txid: '8d23fb69c2941a3f0189aa145db1a0105a232a30b3400551632060f43ad49f88',
	vout: 0,
};

const recipientAddress = 'tb1qmdyklysj3syrs9zsvrekrrd6smgpvc2lm6mpt4'; //Alice's p2wpkh address
const amount = 700;
const scriptPubkey = bitcoin.address.toOutputScript(recipientAddress, TESTNET);

const tx = new bitcoin.Transaction();
tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout, 0xfffffffe);
tx.addOutput(scriptPubkey, amount);

const signatureHash = tx.hashForSignature(0, redeemScript, hashType);

//Path 1: Alice tries to redeem with only her signature if IF statement executed
//Expect: Transaction fails without Bob's signature
// const redeemScriptSig = bitcoin.payments.p2sh({
// 	redeem: {
// 		input: bitcoin.script.compile([
// 			bitcoin.script.signature.encode(alice.sign(signatureHash), hashType),
// 			bitcoin.opcodes.OP_TRUE,
// 		]),
// 		output: redeemScript,
// 	},
// }).input;

//Path 2: Both Alice and Bob sign the transaction with IF statement executed
//Expect: Transaction passes
// const redeemScriptSig = bitcoin.payments.p2sh({
// 	redeem: {
// 		input: bitcoin.script.compile([
// 			bitcoin.script.signature.encode(alice.sign(signatureHash), hashType),
// 			bitcoin.script.signature.encode(bob.sign(signatureHash), hashType),
// 			bitcoin.opcodes.OP_TRUE,
// 		]),
// 		output: redeemScript,
// 	},
// }).input;

//Path 3: Alice signs the transaction without IF statement executed (OP_FALSE)
//Expect: Transaction passes
const redeemScriptSig = bitcoin.payments.p2sh({
	redeem: {
		input: bitcoin.script.compile([bitcoin.script.signature.encode(alice.sign(signatureHash), hashType), bitcoin.opcodes.OP_FALSE]),
		output: redeemScript,
	},
}).input;

if (redeemScriptSig) {
	tx.setInputScript(0, redeemScriptSig);
	console.log('redeemScriptSig ->', tools.toHex(redeemScriptSig));
} else {
	console.error('Error: redeemScriptSig is undefined');
}

console.log('To be broadcast =>', tx.toHex());

//RUN: node opcodes_exploration_testnet.js

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

// const preimage = Buffer.from('Secret');
const preimage = Buffer.from('Secret');
const hash = bitcoin.crypto.sha256(preimage);

console.log('preimage ->', preimage);
console.log('hash ->', hash);

function hashedContract(aQ, hash) {
	return bitcoin.script.fromASM(
		`
        OP_SHA256 ${tools.toHex(hash)} OP_EQUALVERIFY ${tools.toHex(aQ.publicKey)} OP_CHECKSIG
        `
			.trim()
			.replace(/\s+/g, ' '),
	);
}

const redeemScript = hashedContract(alice, hash);

const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
		network: TESTNET,
	},
	network: TESTNET,
});

console.log('address ->', address);

//Spending
const utxo = {
	txid: 'b28d57c06981c82c92a08beea84a3dbc4e47c1e44b3c45bd1856784172cc3b96',
	vout: 0,
};

const recipientAddress = 'tb1qmdyklysj3syrs9zsvrekrrd6smgpvc2lm6mpt4'; //Alice's p2wpkh address
const amount = 4600;
const scriptPubkey = bitcoin.address.toOutputScript(recipientAddress, TESTNET);

const tx = new bitcoin.Transaction(TESTNET);
tx.addInput(Buffer.from(utxo.txid, 'hex').reverse(), utxo.vout);
tx.addOutput(scriptPubkey, amount);

const signatureHash = tx.hashForSignature(0, redeemScript, hashType);

console.log('alice.sign(signatureHash) ->', alice.sign(signatureHash));

const redeemScriptSig = bitcoin.payments.p2sh({
	redeem: {
		input: bitcoin.script.compile([bitcoin.script.signature.encode(alice.sign(signatureHash), hashType), preimage]),
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

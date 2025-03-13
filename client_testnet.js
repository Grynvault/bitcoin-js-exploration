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

const izzulBufferedPrivateKey = process.env.TESTNET_IZZUL_2_BUFFERED_PRIVATE_KEY;
const izzulPrivateKey = Buffer.from(izzulBufferedPrivateKey.toString('hex'), 'hex');

//Using the private key to create a keypair
const izzul = ECPair.fromPrivateKey(izzulPrivateKey);

const hashType = bitcoin.Transaction.SIGHASH_ALL;

const preimage = Buffer.from('Secret');
const hash = bitcoin.crypto.sha256(preimage);

const izzulAddress = bitcoin.payments.p2wpkh({ pubkey: izzul.publicKey, network: TESTNET });
console.log('izzulAddress ->', izzulAddress.address);
console.log('izzul.publicKey ->', izzul.publicKey);

function hashedContract(aQ, hash) {
	return bitcoin.script.fromASM(
		`
        OP_SHA256 ${tools.toHex(hash)} OP_EQUALVERIFY ${tools.toHex(aQ.publicKey)} OP_CHECKSIG
        `
			.trim()
			.replace(/\s+/g, ' '),
	);
}

const redeemScript = hashedContract(izzul, hash);

const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: redeemScript,
		network: TESTNET,
	},
	network: TESTNET,
});

console.log('address ->', address);

const utxo = {
	txid: 'a078f8f1ce2676a8cd301221da918a5a430ed083fe8166b5121056f8c6f5ea9e',
	vout: 0,
	value: 1000,
};

const recipientAddress = 'tb1qy3mwjftsfypn9fpywp8jcg3gq6a6up2fd9whj7'; //Izzul's p2wpkh address
const amount = 600;

const psbt = new bitcoin.Psbt({ network: TESTNET });

// Add the input (UTXO)
psbt.addInput({
	hash: utxo.txid,
	index: utxo.vout,
	nonWitnessUtxo: Buffer.from(
		'020000000001019e08d3a1fc5a72392424327d19068c387548d9045bf1bd30f4c55d8a395fb5c60100000000ffffffff02e80300000000000017a9143ef5f7229012e9ca8f9cb577e406abe8a7bc75e087b1410000000000001600142476e92570490332a424704f2c222806bbae054902483045022100fd435f53a4256adac3d0cf8150e0932427a1cf44dee4808fad25404b3f369d1802202a6112e461223cf188a7db88012360abac4952d5b9564129389d5af6ce38f5560121036617e61ead19cf1697fb4a1081f640c5b335cdbb3a6e6c8ad4dcd55c3719305200000000',
		'hex',
	),
	redeemScript: redeemScript,
});

psbt.addOutput({
	address: recipientAddress,
	value: amount, // Amount to send (in sats)
});

console.log('Unsigned PSBT:', psbt.toBase64());
//Use the pbt.toBase64() to sign with Unisat
const signed = ''; //Signed with Unisat
console.log('Signed by Unisat ->', signed);
const signedPsbt = bitcoin.Psbt.fromHex(signed);
const inputIndex = 0; // Assuming single input
const partialSig = signedPsbt.data.inputs[inputIndex].partialSig[0].signature;
console.log('Extracted Signature:', partialSig.toString('hex'));

// psbt.signInput(0, izzul);

psbt.finalizeInput(0, (inputIndex, input) => {
	const scriptSig = bitcoin.payments.p2sh({
		redeem: { output: redeemScript, input: bitcoin.script.compile([partialSig, preimage]) },
	});

	return {
		finalScriptSig: scriptSig.input, // Manually set the scriptSig
	};
});
console.log('Final TX Hex:', psbt.extractTransaction().toHex());

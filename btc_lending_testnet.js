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

//Init Grynvault account
const grynvaultPrivateKey = process.env.TESTNET_IZZUL_2_BUFFERED_PRIVATE_KEY;
const grynvaultBufferedPrivateKey = Buffer.from(grynvaultPrivateKey.toString('hex'), 'hex');
const grynvault = ECPair.fromPrivateKey(grynvaultBufferedPrivateKey);

const hashType = bitcoin.Transaction.SIGHASH_ALL;

/**
 * 
✅ Spending Path 1: Wait for Timeout (CLTV) - If 
1️⃣ The transaction includes lockTime.
2️⃣ OP_CHECKLOCKTIMEVERIFY prevents spending before lockTime is reached.
3️⃣ Once the timeout expires, only Borrower can sign the transaction.

✅ Spending Path 2: Immediate Spend by bQ.publicKey
1️⃣ If bQ.publicKey signs immediately, OP_ELSE executes.
2️⃣ OP_CHECKSIGVERIFY ensures bQ provides a valid signature.
3️⃣ Then, aQ.publicKey must also sign to spend the funds.
 */

function hashedContract(borrower, lender, locktime, hash) {
	return bitcoin.script.fromASM(
		`
            OP_IF
                ${tools.toHex(bitcoin.script.number.encode(locktime))}
                OP_CHECKLOCKTIMEVERIFY
                OP_DROP
                ${tools.toHex(borrower.publicKey)}
                OP_CHECKSIG
            OP_ELSE
                OP_SHA256 
                ${tools.toHex(hash)} 
                OP_EQUALVERIFY 
                ${tools.toHex(lender.publicKey)} 
                OP_CHECKSIG
            OP_ENDIF
            `
			.trim()
			.replace(/\s+/g, ' '),
	);
}

function utcNow() {
	return Math.floor(Date.now() / 1000);
}

const unixTimestamp = 1742490883;

/**
 *
 * Initialize HTLC Contract
 *
 * Step 1 -> Creating the address for Borrower to lock the funds
 *
 */

/////Initializing variables from Client
//Borrower
const borrowerPubkey = '02ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e9758';
const borrowerBufferedPrivateKey = Buffer.from(borrowerPubkey.toString('hex'), 'hex');
const borrower = ECPair.fromPublicKey(borrowerBufferedPrivateKey);
//Locktime
const lockTime = bip65.encode({ utc: unixTimestamp });
// const lockTime = bip65.encode({ utc: utcNow() + 900 }); //15 mins from now
console.log('lockTime ->', lockTime);
//Hash
const firstPreimage = Buffer.from('secret_for_temporary_htlc');
const firstHash = bitcoin.crypto.sha256(firstPreimage);

////Creating the contract
const initHtclRedeemScript = hashedContract(borrower, grynvault, lockTime, firstHash);
const { address } = bitcoin.payments.p2sh({
	redeem: {
		output: initHtclRedeemScript,
		network: TESTNET,
	},
	network: TESTNET,
});

console.log('Init HTCL Redeem address ->', address);

/**
 *
 * Initialize HTLC Contract
 *
 * Step 2 -> If no loans are initiated, Borrower can wait until timelock to redeem the BTC,
 * Else, if loan is successfull, Grynvault will run the transaction to secure the BTC to Collateral HTLC
 *
 */

/////Initializing variables from Client
const utxo = {
	txid: '2259495573df10603fbf96c15468d73e52a744887c429e466841665c46db8147',
	vout: 0,
	value: 34423,
};

const recipientAddress = 'tb1q3jmfx30rdhglnhvyd7ttt9lr26az3wx26e2hqc'; //Borrower's address
const gasFees = 800;
const amount = utxo.value - gasFees;
console.log('amount ->', amount);

/////Creating the transaction
const psbt = new bitcoin.Psbt({ network: TESTNET });

// Add the input (UTXO)
psbt.addInput({
	hash: utxo.txid,
	index: utxo.vout,
	sequence: 0xfffffffe, // ← lets you enable nLockTime in the transaction
	nonWitnessUtxo: Buffer.from(
		'02000000000101f6418d7715fad413d3a95819d532266d4e2cbcc1fe0a8e3a1d3c428be9ba59b70000000000ffffffff02778600000000000017a91444a34a57f33cb24dccf375303a670dd1e7f601888730160200000000001600148cb69345e36dd1f9dd846f96b597e356ba28b8ca02473044022020a29ddaf603f265dabe12d7c874ed5b6172fd9b47f97c62ee3050117c0add9702203dc17e62ea8552fb0c54b2fbcb1b98ffafefa1ced9534f292b58d44719ceb10a012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975800000000',
		'hex',
	),
	redeemScript: initHtclRedeemScript,
});

psbt.setLocktime(lockTime);
psbt.setInputSequence(0, 0xfffffffe);

/**
 *
 *
 * Ouput for Borrower on Path 1
 *
 *
 *
 * */

psbt.addOutput({
	address: recipientAddress,
	value: amount, // Amount to send (in sats)
});

// /////Signing the transaction using Unisat
console.log('Unsigned PSBT:', psbt.toBase64());
//Use the pbt.toBase64() to sign with Unisat

const signed =
	'70736274ff01005202000000014781db465c664168469e427c8844a7523ed76854c196bf3f6010df73554959220000000000feffffff0157830000000000001600148cb69345e36dd1f9dd846f96b597e356ba28b8ca034ddc67000100df02000000000101f6418d7715fad413d3a95819d532266d4e2cbcc1fe0a8e3a1d3c428be9ba59b70000000000ffffffff02778600000000000017a91444a34a57f33cb24dccf375303a670dd1e7f601888730160200000000001600148cb69345e36dd1f9dd846f96b597e356ba28b8ca02473044022020a29ddaf603f265dabe12d7c874ed5b6172fd9b47f97c62ee3050117c0add9702203dc17e62ea8552fb0c54b2fbcb1b98ffafefa1ced9534f292b58d44719ceb10a012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975800000000220202ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e9758483045022100c5a0755d16ffaed442cadbc4252e262c7143abb99043ab1127b063ea8d6f1238022048a3fd892fe08f2582a36e249169c6f8e194a52038ef8c7c8b1834843d5674f8010104736304034ddc67b1752102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e9758ac67a8207817ded1e17cd65a5ce3c678bfce2461213b43272c4b77426558c6fe8f3726c58821036617e61ead19cf1697fb4a1081f640c5b335cdbb3a6e6c8ad4dcd55c37193052ac680000'; //Signed with Unisat
const signedPsbt = bitcoin.Psbt.fromHex(signed);
const inputIndex = 0; // Assuming single input
const partialSig = signedPsbt.data.inputs[inputIndex].partialSig[0].signature;
console.log('Extracted Signature:', partialSig.toString('hex'));

psbt.finalizeInput(0, (inputIndex, input) => {
	const scriptSig = bitcoin.payments.p2sh({
		redeem: { output: initHtclRedeemScript, input: bitcoin.script.compile([partialSig, bitcoin.opcodes.OP_TRUE]) },
	});

	return {
		finalScriptSig: scriptSig.input, // Manually set the scriptSig
	};
});

/**
 *
 *
 * Ouput for Borrower on Path 2
 *
 *
 *
 * */

// psbt.addOutput({
// 	address: recipientAddress,
// 	value: amount, // Amount to send (in sats)
// });

// psbt.signInput(0, grynvault);

// psbt.finalizeInput(0, (inputIndex, input) => {
// 	const scriptSig = bitcoin.payments.p2sh({
// 		redeem: {
// 			output: initHtclRedeemScript,
// 			input: bitcoin.script.compile([psbt.data.inputs[inputIndex].partialSig[0].signature, , firstPreimage, bitcoin.opcodes.OP_FALSE]),
// 		},
// 	});

// 	return {
// 		finalScriptSig: scriptSig.input, // Manually set the scriptSig
// 	};
// });

////To be broadcast
console.log('Final TX Hex:', psbt.extractTransaction().toHex());

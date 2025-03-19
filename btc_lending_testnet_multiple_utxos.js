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

/**
 *
 * Initialize HTLC Contract
 *
 * Step 1 -> Creating the address for Borrower to lock the funds
 *
 */

/////Initializing variables from Client
//Borrower
const borrowerPubkey = '03fc4fb7d6afbf0c95d314314950087a94df7a97973e2f7c7b757b8f721ac764ed';
const borrowerBufferedPrivateKey = Buffer.from(borrowerPubkey.toString('hex'), 'hex');
const borrower = ECPair.fromPublicKey(borrowerBufferedPrivateKey);
//Locktime
const lockTime = bip65.encode({ utc: 1742371000 });
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
	txid: '25def3779bd8ef42c9af9bc9016b72fb467e661fb83a54c9508b785f406cb09a',
	vout: 0,
	value: 17211,
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
	nonWitnessUtxo: Buffer.from(
		'02000000000101169444dedbf562337d1ad2c4ef8f35f3b4caf5c2fb978b2d61dca87cc99045400000000000ffffffff023b4300000000000017a91414badee1c79ae22bf2724e0cef6f64af7015fdd7878a900000000000002251208dec550f3a6b14a4cd29a3aacc4bf8a6ba12f759f7755ca63bc7fe43bae66d190140d744b7b1d4d9b6b3aedde1c5f80448a137c3665dc45b0f476103453b12cec952e2fd59e299931d13cf86bac0f20eda999735e072f3c159a0b1e923a90484dbe500000000',
		'hex',
	),
	redeemScript: initHtclRedeemScript,
});

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

/////Signing the transaction using Unisat
console.log('Unsigned PSBT:', psbt.toBase64());
//Use the pbt.toBase64() to sign with Unisat

const signed =
	'70736274ff0100520200000001953fcdf8f2191d900fd10a2ba8006793fe842f967ee1c02981d8defa4c202d0a0000000000ffffffff011b400000000000001600148cb69345e36dd1f9dd846f96b597e356ba28b8ca00000000000100c202000000000101169444dedbf562337d1ad2c4ef8f35f3b4caf5c2fb978b2d61dca87cc99045400000000000ffffffff023b4300000000000017a91414badee1c79ae22bf2724e0cef6f64af7015fdd7878a900000000000002251208dec550f3a6b14a4cd29a3aacc4bf8a6ba12f759f7755ca63bc7fe43bae66d190140d744b7b1d4d9b6b3aedde1c5f80448a137c3665dc45b0f476103453b12cec952e2fd59e299931d13cf86bac0f20eda999735e072f3c159a0b1e923a90484dbe500000000220202ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e9758473044022035fc0de3684ad1b87f59e95138271f044abd82a7964074105ba7562ec609334c022039b84a407d337c229b5b7110084f3a5627ae6ecf0032bf9ad0a5e7df117e7aff010104736304d074da67b1752103fc4fb7d6afbf0c95d314314950087a94df7a97973e2f7c7b757b8f721ac764edac67a8207817ded1e17cd65a5ce3c678bfce2461213b43272c4b77426558c6fe8f3726c58821036617e61ead19cf1697fb4a1081f640c5b335cdbb3a6e6c8ad4dcd55c37193052ac680000'; //Signed with Unisat
const signedPsbt = bitcoin.Psbt.fromHex(signed);
const inputIndex = 0; // Assuming single input
const partialSig = signedPsbt.data.inputs[inputIndex].partialSig[0].signature;
console.log('Extracted Signature:', partialSig.toString('hex'));

psbt.finalizeInput(0, (inputIndex, input) => {
	const scriptSig = bitcoin.payments.p2sh({
		redeem: { output: initHtclRedeemScript, input: bitcoin.script.compile([partialSig, firstPreimage, bitcoin.opcodes.OP_TRUE]) },
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

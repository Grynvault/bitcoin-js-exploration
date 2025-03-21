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
const txid = '25def3779bd8ef42c9af9bc9016b72fb467e661fb83a54c9508b785f406cb09a';

// List of UTXOs (Replace with real amounts)
const utxos = [
	{ vout: 0, value: 29838 },
	{ vout: 1, value: 22480 },
	{ vout: 2, value: 22052 },
	{ vout: 3, value: 21710 },
	{ vout: 4, value: 21217 },
	{ vout: 5, value: 18449 },
	{ vout: 6, value: 16411 },
	{ vout: 7, value: 15873 },
	{ vout: 8, value: 15239 },
];

const recipientAddress = 'tb1q3jmfx30rdhglnhvyd7ttt9lr26az3wx26e2hqc'; //Borrower's address

const previousTxHex =
	'02000000000109f6d382f919bca3ec502304f8ead8913cbe363d8d7e5c92cdbf846d563a6b5b630100000000fffffffff2f08da420d2e47d3de51553ff2a521f087508aebb2ebdf8f94b1add4ce6b4f20000000000ffffffff2f0d6e73430be7966ec7006484b5ee888bab08837d3242615e64228d03f03ddb0000000000ffffffff9438252611c4f483ee39817030a3c11866be77a286a0a0e6448f8c10d3212b2d0100000000ffffffff33c9c319cb403408c79eb2e94f3a4e0333e74e604604374471a5d7e0212f74310100000000ffffffff963bcc7241785618bd453c4be4c1474ebc3d4aa8ee8ba0922cc88169c0578db20100000000ffffffff6efec42dd855e7dd9a99c1b97c1237a2d41f2db8e45f7cae2fc7060dacc3cb950000000000ffffffffa66d731e1d1064990e89bb71fe9193edc3d9b14a69ff782009eb69c32546066f0100000000ffffffff7eba53fe36f70feefdd5583527c804efed66b251d4a7675714318f300a50d77b0100000000ffffffff0255a002000000000017a9147160dd5948e215970a4dc814e36afdd726da5e7f87e2280000000000001600148cb69345e36dd1f9dd846f96b597e356ba28b8ca02483045022100de4c3ecb4c3ba5748fd36d0d3be95405a8154dc08c6076085a2ed052f83671230220706fd7c717cb30b13cf9d67532d13052f998e3b8d6859e6f45157ea2f8abd3ad012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e97580248304502210084ee9069f57bccba7320115beca5613e598dca2a32eb1fcafdd72253506d61800220779fb50200c22e428c29415ec08c4a847b63c2fd781833e558404862e5affcba012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975802483045022100e2f18e1eea013b298bfaa5aa01a6d19768e65591f74e881b79f028c7440d2e670220299602e6199a0bdcd41b0a9cdb06a0b62c46de0e1ca09d3f2a5fc99ef629caae012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975802473044022064795c2f8c5c13f9c470c6d7f044295d985f0f6b78cbd88f29334ac10a679bba022078c5d62c473dbfee85c581d517ca244e0e1512008d4e05ac76f31aa95b2c8c30012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e97580247304402201348baccd828de9febd36621f799eeaa12b46983fbbc682d966f2fd2e1ec641a02200d568778a46be55362d50c5ec29b5e8d4f9958a8bcba091298604e21d932dfbf012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975802483045022100b1e916a58a00f692f3591d936672f62ff8055b0ca23eaf14ad6e116f6189577a02202135df6bbc464eb12895ee51ddc2a607ad220ea17471e80d0652e8e8494ca954012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e9758024730440220137985a61b6988f5f766ad99e984b54d6e3959578a617f5ab496abd5ce6506a6022062ced3931f2691a26be145f36a7e71c23f9422a7f302d274c18c422b5f19f0cf012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975802483045022100a3c93333b71ef27edb4aa90fe057e175cb62326f42853a4a5fada70e6d8f02b902203ae592c99507ebcb20c6b51497238821f145c8b2e8ecec2373b0ba16194b69d4012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975802483045022100e3ac0d49bb02e106902a21a263504c63e521aa0741e62e8a38ce4384a9b5e26602207de4440a25d5c74a5f7ad8b2420b03430a0c17946d8340c9926578eedb195669012102ddc59466da05af6e1d64d5009cfd1069bc1e8dba743ac4616875ff71f81e975800000000';

const totalInputValue = utxos.reduce((sum, utxo) => sum + utxo.value, 0);

const gasFees = 800;
const amountToSend = 172117 - gasFees;

console.log('Total Inputs (sats):', totalInputValue);
console.log('Amount to Send (sats):', amountToSend);

/////Creating the transaction
const psbt = new bitcoin.Psbt({ network: TESTNET });

// Add the input (UTXO)

// Add all UTXOs with redeemScript
// utxos.forEach((utxo) => {
// 	psbt.addInput({
// 		hash: txid,
// 		index: utxo.vout,
// 		nonWitnessUtxo: Buffer.from(previousTxHex, 'hex'),
// 		redeemScript: initHtclRedeemScript, // ✅ Include redeemScript here
// 	});
// });

psbt.addInput({
	hash: txid,
	index: 0,
	nonWitnessUtxo: Buffer.from(previousTxHex, 'hex'),
	redeemScript: initHtclRedeemScript, // ✅ Include redeemScript here
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
	value: amountToSend, // Amount to send (in sats)
});

psbt.signInput(0, grynvault);

psbt.finalizeInput(0, (index, input) => {
	const sig = input.partialSig[0].signature;
	const scriptSig = bitcoin.payments.p2sh({
		redeem: {
			output: initHtclRedeemScript,
			input: bitcoin.script.compile([sig, firstPreimage, bitcoin.opcodes.OP_FALSE]),
		},
	});
	return { finalScriptSig: scriptSig.input };
});

////To be broadcast
console.log('Final TX Hex:', psbt.extractTransaction().toHex());

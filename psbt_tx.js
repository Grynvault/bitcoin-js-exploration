/** @format */

import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { randomBytes } from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

/**
 *
 * Setting up the Segwit address (P2WPKH) using private key
 *
 */

const bufferedPrivateKey = process.env.BUFFERED_PRIVATE_KEY;
const privatekey = Buffer.from(bufferedPrivateKey.toString('hex'), 'hex');

//Using the private key to create a keypair
const keypair = ECPair.fromPrivateKey(privatekey);
console.log('pubkey ->', keypair.publicKey);
console.log('privateKey ->', keypair.privateKey);

//This is the address that will be used to send/receive funds
const { address } = bitcoin.payments.p2wpkh({ pubkey: keypair.publicKey });
console.log('address -> ', address);

/**
 *
 * Setting up PSBT Transaction on Transaction ID: afaa7036ee82671945c5b2a80402ef7bc6d8059d532619aca5b1437606dc7c0d
 *
 */

const psbt = new bitcoin.Psbt();
psbt.addInput({
	hash: 'afaa7036ee82671945c5b2a80402ef7bc6d8059d532619aca5b1437606dc7c0d',
	index: 0,
	witnessUtxo: {
		script: Buffer.from('001425c63aa33f74303a797c6969c1e2d34099726f14', 'hex'), //scriptPubKey in raw hex
		value: 2000,
	},
});

//Sending 1800 Sathoshis to this address bc1q3jmfx30rdhglnhvyd7ttt9lr26az3wx2sl3ymt, and 200 as gas fees to the miners
psbt.addOutput({
	address: 'bc1q3jmfx30rdhglnhvyd7ttt9lr26az3wx2sl3ymt',
	value: 1800,
});

psbt.signInput(0, keypair);
psbt.finalizeAllInputs();

const txHex = psbt.extractTransaction().toHex();

//Now we can broadcast the txHex to the Bitcoin Network

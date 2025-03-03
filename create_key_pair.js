/** @format */

import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import * as bitcoin from 'bitcoinjs-lib';
import { randomBytes } from 'crypto';

const rng = () => randomBytes(32);

const ECPair = ECPairFactory(ecc);

const keyPair = ECPair.makeRandom({ rng });
//Save this private key
// Output: <Buffer 93 5b 1d 0e da 99 00 03 a8 92 68 32 40 06 cd a9 bd 51 47 a3 74 50 ea 02 18 13 44 ef 3b d3 9d 3d>
// Save as 935b1d0eda990003a89268324006cda9bd5147a37450ea02181344ef3bd39d3d
console.log('privateKey ->', keyPair.privateKey);

const { address } = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey });
console.log('address -> ', address); //This is the address that will be used to send/receive funds

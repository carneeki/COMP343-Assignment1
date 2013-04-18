/*
 * globals.h
 *
 *  Created on: 18/04/2013
 *      Author: carneeki
 */

#ifndef GLOBALS_H_
#define GLOBALS_H_

/** DEBUG
 * Turn on debugging options through STDERR. Debug can be turned on at compile
 * time through "gcc -DDEBUG=1 ..." or by changing the variable below to 1.
 */
#ifndef DEBUG
#define DEBUG 0
#endif
/* DEBUG */

/*
 * bitset and iostream are needed for many calls to _D(), a debug macro
 */
#if DEBUG
#include <iostream>
#include <bitset>
#endif

/** _D()
 * A preprocessor function to place debugging code in. This code is not included
 * in release binaries, but debug binaries will be substantially large, slow and
 * inefficient.
 */
#if DEBUG
#define _D(code) code
#else
#define _D(code) ;
#endif

/**
 * BLOCK_SIZE - Want to read only 2 bytes at a time
 * Assignment spec says to encrypt 2 bytes at a time, so that's the buffer to
 * fill.
 */
#ifndef BLOCK_SIZE
#define BLOCK_SIZE 2
#endif
/* BLOCK_SIZE*/
/**
 * FEISTEL_ROUNDS
 * Number of rounds for ECB mode. This number is ONE based.
 */
#ifndef FEISTEL_ROUNDS
#define FEISTEL_ROUNDS 8
#endif
/* FEISTEL_ROUNDS */

/**
 * CRYPTO_ROUNDS
 * Number of rounds to execute the whole encryption / decryption algorithm.
 */
#ifndef CRYPTO_ROUNDS
#define CRYPTO_ROUNDS 2
#endif
/* CRYPTO_ROUNDS */

#endif /* GLOBALS_H_ */

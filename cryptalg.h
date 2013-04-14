/*
 * cryptalg.h
 *
 *  Created on: 29/03/2013
 *      Author: carneeki
 */

#ifndef CRYPTALG_H_
#define CRYPTALG_H_

/** DEBUG
 * Turn on debugging options through STDOUT. Debug can be turned on at compile
 * time through "gcc -DDEBUG=1 ..." or by changing the variable below to 1.
 */
#ifndef DEBUG
#define DEBUG 0
#endif
/* DEBUG */

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

using namespace std;

/**
 * key_lut
 * LUT (Look Up Table) for keys in the scheduling algorithm. While slightly more
 * memory intensive (16bits * number of rounds = 128 bits = 16 bytes in default
 * implementation), it means accessing the key for round i is far less CPU
 * intensive (simply look up rather than generate i rounds for each byte to be
 * encrypted). All key rounds are generated prior to an encrypt() or decrypt()
 * operation so they are available for immediate use.
 */
uint8_t key_lut[FEISTEL_ROUNDS];

/**
 * mode
 * Encrypt vs Decrypt operation. Encrypt = 1. Decrypt = 0;
 */
bool mode;

/**
 * starting key
 * This is the key that the user enters in the command line argument to
 * encrypt() / decrypt().
 */
uint16_t starting_key;

void decrypt(uint8_t, uint8_t &, uint8_t&);
void encrypt(uint8_t, uint8_t &, uint8_t&);
void help(char*[]);
void keyreverse();
void keysched(uint8_t, uint8_t*);
uint8_t permute(uint8_t, uint8_t);
uint8_t rol(uint8_t, const uint8_t);

uint8_t sbox(uint8_t);

uint8_t _hi4(uint8_t);
uint8_t _lo4(uint8_t);

uint8_t _hi8(uint16_t);
uint8_t _lo8(uint16_t);

bool _init(int, char*, fstream&, ofstream&);

#endif /* CRYPTALG_H_ */

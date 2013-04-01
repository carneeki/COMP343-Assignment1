/*
 * cryptalg.h
 *
 *  Created on: 29/03/2013
 *      Author: carneeki
 */

#ifndef CRYPTALG_H_
#define CRYPTALG_H_

/** _DEBUG
 * Turn on debugging options through STDOUT
 */
#ifndef DEBUG
#define DEBUG 1
#endif
/* _DEBUG */

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

/**
 * Main encrypt function.
 * Wrapper for all encryption operations.
 * @param infile reference to the input file handle
 * @param outfile reference to the output file handle
 * @param key the key to encrypt with
 * @return 0 on success, 1 on fail
 */
int encrypt(fstream& infile, ofstream& outfile);

/**
 * Feistel Round
 * Perform a round of the cipher as depicted in the Feistel network from the
 * assignment.
 * @param round_num
 * @param left
 * @param right
 */
void feistel_round(uint8_t round, uint8_t *buf);

/**
 * help
 * Help function to display a message showing user how to use the program.
 * Returns 1 and terminates execution.
 * @param argv
 */
void help(char* argv[]);

/**
 * keyreverse
 * Reverse the key schedule for decryption
 * @param key_lut
 */
void keyreverse();

/**
 * keysched
 * Key scheduler algorithm - generate all keys and store in the LUT.
 * @param round
 * @param key
 * @return
 */
void keysched(uint8_t round, uint8_t *key_lut);

/**
 * main
 * main program block
 * @param argc argument count
 * @param argv array of arguments provided
 * @return 0 on success, 1 on failure
 */
int main(int argc, char* argv[]);

/**
 * Permute
 * Permute assemble hi and lo nibbles and permute them by performing a circular
 * left shift (by 2).
 * @param uint8_t *hi hi order nibble
 * @param uint8_t *lo lo order nibble
 * @return uint8_t permuted byte
 */
uint8_t permute(uint8_t hi, uint8_t lo);

/**
 * sbox
 * Lookup function (LUT) for s-box
 * This is a fast function using an array
 * @param input nibble
 * @return output nibble
 */
uint8_t sbox(uint8_t input);

/**
 * Rotate left circular shift operations
 * @param shift amount to rotate by
 * @param input variable to be rotated
 * @return shifted variable leaving original value untouched
 */
uint8_t rol(uint8_t shift, const uint8_t input);

/**
 * Rotate right circular shift operation
 * @param shift amount to rotate by
 * @param input variable to be rotated
 * @return shifted variable leaving original value untouched
 */
uint8_t ror(uint8_t shift, const uint8_t input);

/**
 * hi8
 * Extract 8 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi8(uint16_t input);

/**
 * lo8
 * Extract 8 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo8(uint16_t input);

/**
 * hi4
 * Extract 4 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi4(uint8_t input);

/**
 * lo4
 * Extract 4 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo4(uint8_t input);

bool _init(int argc, char* argv[], fstream &in, ofstream &out);

#endif /* CRYPTALG_H_ */

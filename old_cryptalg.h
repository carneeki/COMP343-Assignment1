/*
 * cryptalg.h
 *
 *  Created on: 29/03/2013
 *      Author: carneeki
 */

#ifndef OLD_CRYPTALG_H_
#define OLD_CRYPTALG_H_

/* BLKSIZE - Want to read only 2 bytes at a time
 *  (1) assignment spec says to encrypt 2 bytes at a time, so that's the buffer
 *      to fill
 *  and
 *  (2) Do not waste RAM on large files - memory usage would otherwise be double
 *      the input file size (need to hold both input AND output) + key. Two
 *      bytes at a time means constant memory utilization.
 *      TODO: determine if this results in performance decrease due to increased
 *      disk i/o operations or not. (maybe read in 1KB at a time, or perhaps
 *      whatever the native filesystem block size is?)
 */
#ifndef BLKSIZE
#define BLKSIZE 2
#endif
/* BLKSIZE*/
/* CBCROUNDS - Number of rounds in CBC mode
 */
#ifndef CBCROUNDS
#define CBCROUNDS 8
#endif
/* CBCROUNDS */

/*
 * CPU_ROL
 * Is used to take advantage of some inline assembly on Intel x86 and AMD64
 * architectures (eg use CPU opcode ROL to rotate left rather than use a slower
 * implementation in C++. If ARCH_X86 or ARCH_A64 is not present, use the slower
 * portable code.
 */
#if MSVC
#ifdef _M_X86
#define CPU_ROL
#endif
#endif

#if GCC
#ifdef __i386__
#define CPU_ROL
#endif
#endif

using namespace std;

int decrypt(fstream& infile, ofstream& outfile, uint16_t key); // decrypt magic
int encrypt(fstream& infile, ofstream& outfile, uint16_t key); // encrypt magic

uint8_t sbox(uint8_t input);                  // LUT for s-box
uint8_t high8(uint16_t input);
uint8_t low8(uint16_t input);
void crypt_round(uint8_t round_num, uint8_t *buf, uint16_t key);

unsigned char rol(const unsigned char value, unsigned char shift);    // rot shift left
unsigned int  rol(const unsigned int  value, unsigned char shift);
unsigned int ror(const unsigned int  value, int shift);    // rot shift right

void help(char* argv[]);                                  // help function

#endif /* CRYPTALG_H_ */

/*
 * cryptalg.h
 *
 *  Created on: 29/03/2013
 *      Author: carneeki
 */

#ifndef CRYPTALG_H_
#define CRYPTALG_H_

/** DEBUG
 * Turn on debugging options through STDERR. Debug can be turned on at compile
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
#define FEISTEL_ROUNDS 2
#endif
/* FEISTEL_ROUNDS */

using namespace std;

void feistel( uint8_t, uint8_t &, uint8_t&,
              const uint16_t (&)[FEISTEL_ROUNDS] );
void help( char*[] );
void keyreverse( uint16_t (&)[FEISTEL_ROUNDS] );
void keysched( uint8_t, uint8_t*, uint16_t (&)[FEISTEL_ROUNDS] );
uint8_t permute( uint8_t, uint8_t );
uint8_t rol( uint8_t, const uint8_t );

uint8_t sbox( uint8_t );

uint8_t _hi4( uint8_t );
uint8_t _lo4( uint8_t );

uint8_t _hi8( uint16_t );
uint8_t _lo8( uint16_t );

bool _init( int, char*, fstream&, ofstream&, uint16_t (&),
            uint16_t (&)[FEISTEL_ROUNDS] );

#endif /* CRYPTALG_H_ */

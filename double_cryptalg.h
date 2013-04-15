/*
 * double_cryptalg.h
 *
 *  Created on: 14/04/2013
 *      Author: carneeki
 */

#ifndef DOUBLE_CRYPTALG_H_
#define DOUBLE_CRYPTALG_H_

#ifndef CRYPTALG_H_
#include "cryptalg.h"
#endif

#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
/**
 * CRYPTO_ROUNDS
 * Number of rounds to execute the encryption / decryption algorithm.
 */
#ifndef CRYPTO_ROUNDS
#define CRYPTO_ROUNDS 2
#endif
/* FEISTEL_ROUNDS */

using namespace std;

/**
 * multi_encrypt
 * Iteratively call the encrypt() function with an almost identical prototype.
 * Each argument is an array of the elements that encrypt() expects of
 * CRYPTO_ROUNDS in size. That is, if performing 2 CRYPTO_ROUNDS (as per
 * assignment spec), encrypt() will be called twice using the [0] and [1]
 * element of each argument.
 * @param Li
 * @param Ri
 * @param key_lut
 */
void multi_feistel( uint8_t (&Li)[CRYPTO_ROUNDS], uint8_t (&Ri)[CRYPTO_ROUNDS],
                    const uint16_t (&key_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS] )
{
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    feistel( 0, Li[i], Ri[i], key_lut[i] );
  }
}

/**
 * double_init
 * Set up and sanitize variables as per spec, but create multiple key look up
 * tables for each cryptographic round to be executed (two per spec).
 * @param argc
 * @param argv
 * @param in
 * @param out
 * @param starting_key
 * @param key_lut
 * @param mode
 * @return
 */
bool double_init( int argc, char* argv[], fstream &in, ofstream &out,
                  uint32_t &starting_key,
                  uint16_t (&key_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS],
                  bool &mode )
{

  _D( fprintf(stdout, "double_init(): starting\n"); )

  // Show a friendly help message
  if( argc != 5 )
  {
    help( argv );
  }

  char *strin;           // relative path to input file
  char *strout;          // relative path to output file
  char *oper;            // operation: E = encrypt / D = decrypt
  unsigned long inlen;   // input file length
  uint16_t s_key[CRYPTO_ROUNDS]; // starting key for each cryptographic round

  strin = argv[1];
  strout = argv[2];
  starting_key = (uint32_t) strtoul( argv[3], NULL, 0 );
  oper = argv[4];

  in.open( strin, ios::binary | ios::in | ios::out | ios::ate );
  out.open( strout, ios::binary | ios::out | ios::trunc );

  // do sanity checks on files now
  if( !in.good() )
  {
    fprintf( stderr, "FATAL: input file %s could not be opened. Quitting.\n",
             strin );
    exit( EXIT_FAILURE );
  }
  if( !out.good() )
  {
    fprintf( stderr, "FATAL: input file %s could not be opened. Quitting.\n",
             strin );
    exit( EXIT_FAILURE );
  }

  if( ( inlen = in.tellg() ) == 0 )
  {
    // empty file
    fprintf( stderr, "FATAL: input file %s is empty. Quitting.\n", strin );
    exit( EXIT_FAILURE );
  }

  // assume input files are openable
  if( ( *oper == 'E' ) || ( *oper == 'e' ) )
  {
    mode = 1;

    // check length of input for odd number bytes, pad to even
    if( ( inlen % 2 ) == 1 )
    {

      _D( fprintf(stdout, "double_init(): in length has odd number bytes (%ld). Appending a zero.\n", inlen); )

      in.seekp( inlen );
      in.write( "\0", 1 );
      in.flush();
    }
  }
  else if( ( *oper == 'D' ) || ( *oper == 'd' ) )
  {
    mode = 0;

    // check length of input for odd number bytes, abort if odd number (bad data)
    if( ( inlen % 2 ) == 1 )
    {
      fprintf(
          stderr,
          "FATAL: cannot decrypt input file %s with odd number of bytes %ld\n",
          strin, inlen );
    }
  }
  else
  {
    help( argv );
    exit( EXIT_FAILURE );
  }

  in.seekp( in.beg ); // ensure pointers are definitely at START of file.
  in.seekg( in.beg );

  _D( fprintf(stdout, "double_init(): in: %s out: %s key: 0x%04x rounds: %d mode: %s \n", strin, strout, starting_key, FEISTEL_ROUNDS, oper); )

  // get the starting key for each cryptographic round
  s_key[0] = return ( starting_key & ( ( 1 << 16 ) - 1 ) );
  s_key[1] = starting_key;

  // generate key lookup tables for each cryptographic round
  for(int i = 0; i < CRYPTO_ROUNDS; i++)
  {
    keysched( 0, s_key[i], key_lut[i] );
  }

  return mode;
}

#endif /* DOUBLE_CRYPTALG_H_ */

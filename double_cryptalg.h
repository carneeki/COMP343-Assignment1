/*
 * double_cryptalg.h
 *  Created on: 14/04/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */
#ifndef DOUBLE_CRYPTALG_H_
#define DOUBLE_CRYPTALG_H_

#ifndef GLOBALS_H_
#include "globals.h"
#endif

#ifndef HELPERS_H_
#include "helpers.h"
#endif

/**
 * double_init
 * Set up and sanitize variables as per spec, but create multiple key look up
 * tables for each cryptographic round to be executed (two per spec).
 * @see init
 * @param argc
 * @param argv
 * @param in
 * @param out
 * @param starting_key
 * @param key_lut
 * @param mode
 * @return mode
 */
bool double_init( int argc, char* argv[], fstream &in, ofstream &out,
                  uint32_t &starting_key,
                  uint16_t (&key_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS],
                  bool &mode );
/**
 * help
 * Help function to display a message showing user how to use the program.
 * Returns 1 and terminates execution.
 * @param argv
 */
void help( char* argv[] );

/**
 * main()
 * Main program block
 * @param argc Argument count
 * @param argv Argument values
 * @return
 */
int main( int argc, char* argv[] );

/**
 * multi_feistel
 * Iteratively call the feistel() function with an almost identical prototype.
 * Each argument is an array of the elements that feistel() expects of
 * CRYPTO_ROUNDS in size. That is, if performing 2 CRYPTO_ROUNDS (as per
 * assignment spec), feistel will be called twice using the [0] and [1]
 * element of array based arguments
 * @param Li
 * @param Ri
 * @param key_lut[][]
 */
void multi_feistel( uint8_t (&l), uint8_t (&r),
                    const uint16_t (&key_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS] );

/**
 * multi_keyreverse
 * Reverse the keyschedule and then reverse the order of schedules
 * @param ekey_lut LUT for encryption keyschedule
 * @param dkey_lut LUT for decryption keyschedule
 */
void multi_keyreverse(
    const uint16_t (&ekey_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS],
    uint16_t (&dkey_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS] );

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
// Function definitions below this point.
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

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
  s_key[0] = _hi16( starting_key );
  s_key[1] = _lo16( starting_key );

  // generate key lookup tables for each cryptographic round
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    keysched( 0, s_key[i], key_lut[i] );
  }

  return mode;
} /* double_init() */

void help( char* argv[] )
{
  fprintf( stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0] );
  return;
} /* help() */

void multi_feistel( uint8_t (&l), uint8_t (&r),
                    const uint16_t (&key_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS] )
{
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    feistel( 0, l, r, key_lut[i] );
} /* multi_feistel() */

void multi_keyreverse(
    const uint16_t (&ekey_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS],
    uint16_t (&dkey_lut)[CRYPTO_ROUNDS][FEISTEL_ROUNDS] )
{
  // reverse key schedule for decryption
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    for( int j = 0; j < FEISTEL_ROUNDS; j++ )
      dkey_lut[abs( i - ( CRYPTO_ROUNDS - 1 ) )][abs(
          j - ( FEISTEL_ROUNDS - 1 ) )] = ekey_lut[i][j];
} /* multi_keyreverse */

#endif /* DOUBLE_CRYPTALG_H_ */

/*
 * helpers.h
 *
 *  Created on: 12/04/2013
 *      Author: carneeki
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#ifndef CRYPTALG_H_
#include "cryptalg.h"
#endif

#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream

/**
 * Feistel Round - Decrypt
 * Perform all rounds of the cipher as depicted in the Feistel network from the
 * assignment. This is a recursive algorithm.
 * @param round_num
 * @param left
 * @param right
 */
void decrypt( uint8_t round, uint8_t &Li, uint8_t &Ri,
              const uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{
  _D( fprintf(stdout, "decrypt(%d): starting\n", round); )

  // check we are not doing too many rounds
  if( round == FEISTEL_ROUNDS )
  {
    return;
  }

  uint8_t next; // Li_Next or Ri_Next (depends on encrypt vs decrypt)
  uint8_t tmp;  // temporary scratch space

  /* Decrypt:
   * F-BOX :: START
   * 1. Li XOR Ki
   * 2. sbox hi and lo nibble
   * 3. combine nibbles and permute
   * F-BOX :: END
   *
   * 4. LiNext = Ri XOR permute
   * 5. RiNext = Li
   * 6. Send to next Feistel round
   */

  // F-BOX :: START
  // 1. Li XOR Ki
  tmp = Li ^ key_lut[round];

  // 2. sbox lo and hi nibble
  // 3. combine nibbles and permute
  tmp = permute( sbox( _hi4( tmp ) ), sbox( _lo4( tmp ) ) );
  // F-BOX :: END

  // 4. LiNext = Ri XOR permute
  // 5. RiNext = Li... Just pass Li
  next = Ri ^ tmp;

  // call recursively, but not too many times
  if( round + 1 < FEISTEL_ROUNDS )
  {
    decrypt( round + 1, next, Li, key_lut );
  }

  // update references for 'return' to parent
  Ri = Li;
  Li = next;
}

/**
 * Feistel Round - Encrypt
 * Perform all rounds of the cipher as depicted in the Feistel network from the
 * assignment. This is a recursive algorithm.
 * @param round_num
 * @param left
 * @param right
 */
void encrypt( uint8_t round, uint8_t &Li, uint8_t &Ri,
              const uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{
  _D( fprintf(stdout, "encrypt(%d): starting\n", round); )

  // check we are not doing too many rounds
  if( round == FEISTEL_ROUNDS )
  {
    return;
  }

  uint8_t next; // Li_Next or Ri_Next (depends on encrypt vs decrypt)
  uint8_t tmp;  // temporary scratch space

  /* Encrypt:
   * F-BOX :: START
   * 1. Ri XOR Ki
   * 2. sbox hi and lo nibble
   * 3. combine nibbles and permute
   * F-BOX :: END
   *
   * 4. RiNext = Li XOR permute
   * 5. LiNext = Ri
   * 6. Send to next Feistel round
   */

  // F-BOX :: START
  // 1. Ri XOR Ki
  tmp = ( Ri ^ key_lut[round] );

  _D( fprintf(stdout, "encrypt(%d): Ri XOR Ki = 0x%02x     ^ 0x%02x\n", round,Ri, key_lut[round]); bitset<8> bRi(Ri); bitset<8> bKi(key_lut[round]); bitset<8> btmp(tmp); cout << "feistel_round() : Ri ^ Ki   = " << bRi << " ^ " << bKi << "=" << btmp << endl; );

  // 2. sbox lo and hi nibble
  // 3. combine nibbles and permute
  tmp = permute( sbox( _hi4( tmp ) ), sbox( _lo4( tmp ) ) );
  // F-BOX :: END

  // 4. RiNext = Li XOR permute
  // 5. LiNext = Ri... Just pass Ri
  next = Li ^ tmp;

  // call recursively, but not too many times
  if( round + 1 < FEISTEL_ROUNDS )
  {
    encrypt( round + 1, Ri, next, key_lut );
  }
  // update 'return' references
  Li = Ri;
  Ri = next;
}

/**
 * help
 * Help function to display a message showing user how to use the program.
 * Returns 1 and terminates execution.
 * @param argv
 */
void help( char* argv[] )
{
  fprintf( stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0] );
  return;
}

/**
 * keyreverse
 * Reverse the key schedule for decryption
 * @param key_lut
 */
void keyreverse( uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{
  uint8_t tkey;            // temporary placeholder for key reversal

  _D( fprintf(stdout, "keyreverse(): starting\n"); )

  /*****************************************************************************
   *         Important difference between encryption and decryption:
   *                       REVERSE THE KEY SCHEDULE!
   ****************************************************************************/
  for( int i = 0; i < ( FEISTEL_ROUNDS - ( ( FEISTEL_ROUNDS + 1 ) / 2 ) ); i++ )
  {
    tkey = key_lut[i];
    key_lut[i] = key_lut[ ( FEISTEL_ROUNDS - 1 ) - i];
    key_lut[ ( FEISTEL_ROUNDS - 1 ) - i] = tkey;
  }

  _D( for (int i = 0; i < FEISTEL_ROUNDS; i++) fprintf(stdout, "keyreverse(%d): key_lut[%d] = 0x%02x\n", i, i, key_lut[i]); )

}

/**
 * keysched
 * Key scheduler algorithm - generate all keys and store in the LUT.
 * @param round
 * @param key
 * @return
 */
void keysched( uint8_t round, const uint16_t &starting_key,
               uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{

  _D( fprintf(stdout, "keysched(%d): starting ", round); )

  // check we are not generating too many keys
  if( round == FEISTEL_ROUNDS )
  {
    return;
  }
  else if( round == 0 ) // K0 = bits 7..0
  {
    key_lut[round] = _lo8( starting_key );
  }
  else if( round == 1 ) // K1 = bits 15..8
  {
    key_lut[round] = _hi8( starting_key );
  }
  else
  {
    // Ki = ROTL^3(Ki-1) xor ROTL^5(Ki-2) | i = 2..7
    key_lut[round] = rol( 3, key_lut[round - 1] )
        ^ rol( 5, key_lut[round - 2] );
  }
  _D( fprintf(stdout, "key_lut[%d] = 0x%02x\n", round, key_lut[round]); )

  // call recursively, but not too many times
  if( round + 1 < FEISTEL_ROUNDS )
  {
    keysched( round + 1, starting_key, key_lut );
  }
  return;
}

/**
 * main
 * main program block
 * @param argc argument count
 * @param argv array of arguments provided
 * @return 0 on success, 1 on failure
 */
//int main(int argc, char* argv[]);
/**
 * Permute
 * Permute assemble hi and lo nibbles and permute them by performing a circular
 * left shift (by 2).
 * @param uint8_t *hi hi order nibble
 * @param uint8_t *lo lo order nibble
 * @return uint8_t permuted byte
 */
uint8_t permute( uint8_t hi, uint8_t lo )
{

  _D( fprintf(stdout, "permute(): starting\n"); )

  // combine nibbles to get byte
  uint8_t combined = ( ( hi << 4 ) | lo );
  uint8_t rolCombined = rol( 2, combined );

  _D( std::bitset<8> bCombined(combined); std::bitset<8> bRolCombined(rolCombined);

  fprintf(stderr, "permute(): combined: "); cerr << bCombined << " rotated: " << bRolCombined << endl; )

  return rolCombined;
}

/**
 * sbox
 * Lookup function (LUT) for s-box
 * This is a fast function using an array
 * @param input nibble
 * @return output nibble
 */
uint8_t sbox( uint8_t input )
{

  _D( fprintf(stdout, "sbox(0x%x): ", input); )

  uint8_t lut[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };

  _D( bitset<8> bSbox(lut[input]); cout << bSbox << endl; )

  return lut[input];
}

/**
 * Rotate left circular shift operations
 * @param shift amount to rotate by
 * @param input variable to be rotated
 * @return shifted variable leaving original value untouched
 */
uint8_t rol( uint8_t shift, const uint8_t input )
{
  return ( input << shift ) | ( input >> ( sizeof ( input ) * 8 - shift ) );
}

/**
 * hi8
 * Extract 8 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi8( uint16_t input )
{
  return ( input >> 8 );
}

/**
 * lo8
 * Extract 8 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo8( uint16_t input )
{
  return ( input & ( ( 1 << 8 ) - 1 ) );
}

/**
 * hi4
 * Extract 4 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi4( uint8_t input )
{
  return ( input >> 4 );
}

/**
 * lo4
 * Extract 4 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo4( uint8_t input )
{
  return ( input & ( ( 1 << 4 ) - 1 ) );
}

bool _init( int argc, char* argv[], fstream &in, ofstream &out,
            uint16_t &starting_key, uint16_t (&key_lut)[FEISTEL_ROUNDS],
            bool &mode )
{

  _D( fprintf(stdout, "_init(): starting\n"); )

  // Show a friendly help message
  if( argc != 5 )
  {
    help( argv );
  }

  char *strin;           // relative path to input file
  char *strout;          // relative path to output file
  char *oper;            // operation: E = encrypt / D = decrypt
  unsigned long inlen;   // input file length

  strin = argv[1];
  strout = argv[2];
  starting_key = (uint16_t) strtoul( argv[3], NULL, 0 );
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

      _D( fprintf(stdout, "_init(): in length has odd number bytes (%ld). Appending a zero.\n", inlen); )

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

  _D( fprintf(stdout, "_init(): in: %s out: %s key: 0x%04x rounds: %d mode: %s \n", strin, strout, starting_key, FEISTEL_ROUNDS, oper); )

  keysched( 0, starting_key, key_lut );

  return mode;
}

#endif /* HELPERS_H_ */

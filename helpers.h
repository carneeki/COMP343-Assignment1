/*
 * helpers.h
 *
 *  Created on: 12/04/2013
 *      Author: carneeki
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#ifndef GLOBALS_H_
#include "globals.h"
#endif

#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
#include <iostream>
#include <iomanip>
#include <map>      // map
#include <ctime>    // time

/**
 * lr_pair
 * A pairing of a cryptogram or message (left+right parts) to form an index for
 * mapping either messages or cryptograms with key_pairs
 */
struct lr_pair
{
    uint8_t l; // left part
    uint8_t r; // right part

    bool operator==( const lr_pair &other ) const
    {
      return ( ( l == other.l ) && ( r == other.r ) );
    }/* operator== */

    bool operator<( const lr_pair &other ) const
    {
      if( l < other.l )
        return true;
      else if( ( l == other.l ) && ( r < other.r ) )
        return true;
      else
        return false;
    } /* operator< */

    friend std::ostream& operator<<( ostream &os, const lr_pair &lr )
    {
      os << "0x" << setfill( '0' ) << setw( 2 ) << hex << (int) lr.l
         << " "
         << "0x" << setfill( '0' ) << setw( 2 ) << hex << (int) lr.r;
      return os;
    } /* operator<< */
};

/**
 * key_pair
 * Hold 2 keys, k1 and k2 together
 */
struct key_pair
{
    uint16_t k1; // key 1
    uint16_t k2; // key 2

    bool operator<( const key_pair &kp ) const
    {
      if( k1 < kp.k1 )
        return true;
      else if( ( k1 == kp.k1 ) && ( k2 < kp.k2 ) )
        return true;
      else
        return false;
    } /* operator< */

    friend ostream& operator<<( ostream &os, const key_pair &kp )
    {
      os << "0x" << setfill( '0' ) << setw( 4 ) << hex << (long int) kp.k1
         << " " << "0x" << setfill( '0' ) << setw( 4 ) << hex
         << (long int) kp.k2;
      return os;
    } /* operator<< */
}; /* struct key_pair */

/**
 * Feistel Round - feistel
 * Perform all rounds of the cipher as depicted in the Feistel network from the
 * assignment. This is a recursive algorithm.
 * @param round_num
 * @param left
 * @param right
 * @param key_lut
 */
void feistel( uint8_t f_round, uint8_t &l, uint8_t &r,
              const uint16_t (&key_lut)[FEISTEL_ROUNDS] );

/**
 * keyreverse
 * Reverse the key schedule for decryption
 * @param key_lut
 */
void keyreverse( const uint16_t (&ekey_lut)[FEISTEL_ROUNDS],
                 uint16_t (&dkey_lut)[FEISTEL_ROUNDS] );

/**
 * keysched
 * Key scheduler algorithm - generate all keys and store in the LUT.
 * @param round
 * @param key
 * @return
 */
void keysched( uint8_t round, const uint16_t &starting_key,
               uint16_t (&key_lut)[FEISTEL_ROUNDS] );

/**
 * Permute
 * Permute assemble hi and lo nibbles and permute them by performing a circular
 * left shift (by 2).
 * @param uint8_t hi hi order nibble
 * @param uint8_t lo lo order nibble
 * @return uint8_t permuted byte
 */
uint8_t permute( uint8_t hi, uint8_t lo );

/**
 * Rotate left circular shift operations
 * @param shift amount to rotate by
 * @param input variable to be rotated
 * @return shifted variable leaving original value untouched
 */
uint8_t rol( uint8_t shift, const uint8_t input );

/**
 * sbox
 * Lookup function (LUT) for s-box
 * This is a fast function using an array
 * @param input nibble
 * @return output nibble
 */
uint8_t sbox( uint8_t input );

/**
 * hi16
 * Extract 16 high order bits from integer
 * @param input
 * @return
 */
uint16_t _hi16( uint32_t input );


/**
 * hi4
 * Extract 4 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi4( uint8_t input );


/**
 * hi8
 * Extract 8 high order bits from integer
 * @param input
 * @return
 */
uint8_t _hi8( uint16_t input );

/**
 * lo16
 * Extract 16 low order bits from 32 bit integer
 * @param input
 * @return
 */
uint16_t _lo16( uint32_t input );

/**
 * lo4
 * Extract 4 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo4( uint8_t input );

/**
 * lo8
 * Extract 8 low order bits from integer
 * @param input
 * @return
 */
uint8_t _lo8( uint16_t input );

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
// Function definitions below this point.
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

void feistel( uint8_t f_round, uint8_t &l, uint8_t &r,
              const uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{
  _D(
      fprintf( stderr, "      encrypt(%d): starting\n", f_round );
      fprintf( stderr, "                : Li = 0x%2x\n", l );
  ); /* _D() */

  // check we are not doing too many rounds
  if( f_round == FEISTEL_ROUNDS )
    return;

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
  tmp = ( r ^ key_lut[f_round] );

  _D(
      fprintf(
          stderr, "                : Ri ^ Ki = 0x%02x ^\n                :           0x%02x\n",
          r, key_lut[f_round]);
      std::bitset<8> bRi(r);
      std::bitset<8> bKi(key_lut[f_round]);
      std::bitset<8> btmp(tmp);
      cerr << "                :         = " << bRi << " ^" << endl
           << "                :           " << bKi         << endl
           << "                :         = " << btmp        << endl;
  ); /* _D() */

  // 2. sbox lo and hi nibble
  // 3. combine nibbles and permute
  // 4. RiNext = Li XOR permute
  // 5. LiNext = Ri
  l = l ^ permute( sbox( _hi4( tmp ) ), sbox( _lo4( tmp ) ) );

  _D(
      bitset<8> bLi(l);
      btmp = bitset<8>(tmp);
      fprintf(stderr, "      encrypt(%d): next = Li ^ tmp\n", f_round);
      cerr << "                : " << bLi << " ^"
           << "                : " << btmp  << endl;
  ); /* _D() */

  // call recursively, but not too many times
  // and swap our left and rights!
  if( f_round + 1 < FEISTEL_ROUNDS )
    feistel( f_round + 1, r, l, key_lut );

  // update 'return' references
//  l = r;
//  r = tmp;

} /* feistel() */

void keyreverse( const uint16_t (&ekey_lut)[FEISTEL_ROUNDS],
                 uint16_t (&dkey_lut)[FEISTEL_ROUNDS] )
{
  _D( fprintf(stdout, "    keyreverse(): starting\n"); )

  /*****************************************************************************
   *         Important difference between encryption and decryption:
   *                       REVERSE THE KEY SCHEDULE!
   ****************************************************************************/
  for( int i = 0; i < FEISTEL_ROUNDS; i++ )
    dkey_lut[abs( i - ( FEISTEL_ROUNDS - 1 ) )] = ekey_lut[i];

  _D(
      for (int i = 0; i < FEISTEL_ROUNDS; i++)
      {
        fprintf( stdout, "   keyreverse(%d): ekey_lut[%d] = 0x%02x\n",
                 i, i, ekey_lut[i] );
        fprintf( stdout, "   keyreverse(%d): ekey_lut[%d] = 0x%02x\n",
                 i, i, dkey_lut[i] );
      }
  ); /* _D() */
} /* keyreverse */

void keysched( uint8_t round, const uint16_t &starting_key,
               uint16_t (&key_lut)[FEISTEL_ROUNDS] )
{

  _D( fprintf(stdout, "     keysched(%d): starting", round); );

  // check we are not generating too many keys
  if( round == FEISTEL_ROUNDS )
    return;
  else if( round == 0 ) // K0 = bits 7..0
    key_lut[round] = _lo8( starting_key );
  else if( round == 1 ) // K1 = bits 15..8
    key_lut[round] = _hi8( starting_key );
  else
    // Ki = ROTL^3(Ki-1) xor ROTL^5(Ki-2) | i = 2..7
    key_lut[round] = rol( 3, key_lut[round - 1] )
        ^ rol( 5, key_lut[round - 2] );

  _D(
      fprintf(stdout, " : key_lut[%d] = 0x%02x\n",
      round, key_lut[round]);
  ); /* _D() */

  // call recursively, but not too many times
  if( round + 1 < FEISTEL_ROUNDS )
    keysched( round + 1, starting_key, key_lut );

  return;
} /* keysched() */

uint8_t permute( uint8_t hi, uint8_t lo )
{
  _D(
      std::bitset<8> bHi(hi);
      std::bitset<8> bLo(lo);
      cerr << "       permute(): " << endl;
      cerr << "                :       hi: " << bHi << endl
           << "                :       lo: " << bLo << endl;
  ); /* _D() */

  // combine nibbles to get byte
  uint8_t combined = ( ( hi << 4 ) | lo );
  uint8_t rolCombined = rol( 2, combined );

  _D(
      std::bitset<8> bCombined(combined);
      std::bitset<8> bRolCombined(rolCombined);
      cerr << "                : combined: " << bCombined
           << "                :  rotated: " << bRolCombined << endl;
  ); /* _D() */

  return rolCombined;
} /* permute() */

uint8_t rol( uint8_t shift, const uint8_t input )
{
  return ( input << shift ) | ( input >> ( sizeof ( input ) * 8 - shift ) );
} /* rol() */

uint8_t sbox( uint8_t input )
{

  _D( fprintf(stdout, "       sbox(0x%x): ", input); )

  uint8_t lut[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };

  _D( bitset<8> bSbox(lut[input]); cout << bSbox << endl; )

  return lut[input];
} /* sbox() */

uint16_t _hi16( uint32_t input ) { return ( input >> 16 );               }

uint8_t _hi4( uint8_t input )    { return ( input >> 4 );                }

uint8_t _hi8( uint16_t input )   { return ( input >> 8 );                }

uint16_t _lo16( uint32_t input ) { return (uint16_t) ( input & 0xFFFF ); }

uint8_t _lo4( uint8_t input )    { return ( input & 0xF );               }

uint8_t _lo8( uint16_t input )   { return (uint16_t) ( input & 0xFF );   }

#endif /* HELPERS_H_ */

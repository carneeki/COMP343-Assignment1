/*
 * double_attack_cipher.h
 *
 *  Created on: 14/04/2013
 *      Author: carneeki
 */

#ifndef DOUBLE_ATTACK_CIPHER_H_
#define DOUBLE_ATTACK_CIPHER_H_

#ifndef HELPERS_H_
#include "helpers.h"
#endif

#ifndef CRYPTALG_H_
#include "cryptalg.h"
#endif

#ifndef DOUBLE_CRYPTALG_H_
#include "double_cryptalg.h"
#endif

#include <iomanip>

/**
 * lr_pair
 * A pairing of a cryptogram or message (left+right parts) to form an index for
 * mapping either messages or cryptograms with key_pairs
 */
struct lr_pair
{
    uint8_t l; // left part
    uint8_t r; // right part
    bool operator<( const lr_pair &other ) const
    {
      if( l < other.l && r < other.r ) return true;
      else if( l == other.l && r < other.r ) return true;
      else
        return false;
    }
    friend ostream& operator<<( ostream &os, const lr_pair &lr )
    {
      os << "0x" << setfill( '0' ) << setw( 2 ) << hex << (int) lr.l << " "
         << "0x" << setfill( '0' ) << setw( 2 ) << hex << (int) lr.r;
      return os;
    }
};

/**
 * observation
 * container of message and cryptogram
 */
struct observation
{
    lr_pair m; // msg
    lr_pair c; // cryptogram
    friend ostream& operator<<( ostream &os, const observation &ob )
    {
      os << ob.m << " " << ob.c;
      return os;
    }
};

/**
 * key_pair
 * Hold 2 keys, k1 and k2 together
 */
struct key_pair
{
    uint16_t k1; // key1
    uint16_t k2; // key2
    friend ostream& operator<<( ostream &os, const key_pair &kp )
    {
      os << "0x" << setfill( '0' ) << setw( 4 ) << hex << (int) kp.k1 << ", "
         << "0x" << setfill( '0' ) << setw( 4 ) << hex << (int) kp.k2;
      return os;
    }
};

/**
 * Encrypt observations using unknown random keys from known input messages
 * @param ob
 */
void encrypt_observations( observation (&ob)[CRYPTO_ROUNDS] )
{
  uint16_t s_key[CRYPTO_ROUNDS];
  uint16_t key_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS];

  srand( time( 0 ) );
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    s_key[i] = rand();
    fprintf( stdout, "Starting key (ssh! don't tell main()!) [%d] = %04x\n", i,
             s_key[i] );
    keysched( 0, s_key[i], key_lut[i] );
    multi_feistel( ob[i].m.l, ob[i].m.r, key_lut );
  }
}

/**
 * Generate two random observations and pass them back to main.
 */
void generate_observations( observation (&ob)[CRYPTO_ROUNDS] )
{
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    ob[i].m.l = rand();
    ob[i].m.r = rand();

    // copy the messag to the cryptogram space so multi_feistels does not
    // clobber them in the pass by reference
    ob[i].c = ob[i].m;
  }
}

#endif /* DOUBLE_ATTACK_CIPHER_H_ */

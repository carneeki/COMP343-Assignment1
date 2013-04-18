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
    bool operator==( const lr_pair &other ) const
    {
      if( ( l == other.l ) && ( r == other.r ) )
      {
        return true;
      }
      else
      {
        return false;
      }
    }
    bool operator<( const lr_pair &other ) const
    {
      if( l < other.l )
      {
        return true;
      }
      else if( ( l == other.l ) && ( r < other.r ) )
      {
        return true;
      }
      else
      {
        return false;
      }
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
 * container of message and cryptogram of 16 bit length
 */
struct observation
{
    lr_pair m; // msg
    lr_pair c; // cryptogram
    bool operator==(const observation &other) const
    {
      return ((m == other.m) && (c == other.m));
    }
    friend ostream& operator<<( ostream &os, const observation &ob )
    {
      os << ob.m << " " << ob.c;
      return os;
    }
};

/**
 * table_idx
 * Index for multimap tables, 32 bits in length. Can contain a 32 bit cryptogram
 * or message - designed for holding the middle value for meet in the middle
 * attack.
 */
struct table_idx
{
    lr_pair v1; // value 1
    lr_pair v2; // value 2

    bool operator==( const table_idx &other ) const
    {
      if( ( v1 == other.v1 ) && ( v2 == other.v2 ) )
      {
        return true;
      }
      else if( ( v1.l == other.v1.l ) || ( v2.l == other.v2.l )
               || ( v1.r == other.v1.r ) || ( v2.r == other.v2.r ) )
      {
        return true;
      }
      else
      {
        return false;
      }
    }

    bool operator<( const table_idx &other ) const
    {
      if( v1 < other.v1 )
      {
        return true;
      }
      else if( ( v1 == other.v1 ) && ( v2 < other.v2 ) )
      {
        return true;
      }
      else
      {
        return false;
      }
    }

    friend ostream& operator<<( ostream &os, const table_idx &tbl )
    {
      os << tbl.v1 << " " << tbl.v2;
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
    bool operator<( const key_pair &kp ) const
    {
      if( k1 < kp.k1 ) return true;
      else if( ( k1 == kp.k1 ) && ( k2 < kp.k2 ) ) return true;
      else
        return false;
    }
    friend ostream& operator<<( ostream &os, const key_pair &kp )
    {
      os << "0x" << setfill( '0' ) << setw( 4 ) << hex << (long int) kp.k1
         << " " << "0x" << setfill( '0' ) << setw( 4 ) << hex
         << (long int) kp.k2;
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
  uint16_t ekey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS];

  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    s_key[i] = rand();

    _D(
      s_key[0] = 0xFEED;
      s_key[1] = 0xCAFE;
    );
    fprintf( stdout,
             "Starting key (ssh! don't tell main()!) [%d] = 0x%04x\n", i,
             s_key[i] );
    keysched( 0, s_key[i], ekey_lut[i] );
  }

  // need the same loop a second time because key generation is not
  // complete until all loops are completed above
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    multi_feistel( ob[i].c.l, ob[i].c.r, ekey_lut );
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

    _D(
      ob[0].m.l = 0x41;
      ob[0].m.r = 0x44;
      ob[1].m.l = 0x41;
      ob[1].m.r = 0x4d;
    );

    // copy the message to the cryptogram space so multi_feistels does not
    // clobber them in the pass by reference
    ob[i].c = ob[i].m;
  }
}

void multimap_intersect( const multimap<table_idx, uint16_t> &T_e,
                         const multimap<table_idx, uint16_t> &T_d,
                         multimap<table_idx, key_pair> &T_k )
{
  multimap<table_idx, uint16_t>::const_iterator it_e; // iterator T_e
  multimap<table_idx, uint16_t>::const_iterator it_d; // iterator T_e

  key_pair kp; // key pair from T_e and T_d

  for( it_e = T_e.begin(); it_e != T_e.end(); ++it_e )
  {
    for( it_d = T_d.equal_range( it_e->first ).first;
        it_d != T_d.equal_range( it_e->first ).second; ++it_d )
    {
      // if it_d idx matches it_e idx, add to T_k
      //cout << "iterating it_e:it_d " << it_e->first << " : " << it_d->first
      //     << endl;
      if( it_e->first == it_d->first )
      {
        kp.k1 = it_e->second;
        kp.k2 = it_d->second;
        T_k.insert( std::pair<table_idx, key_pair>( it_e->first, kp ) );
      }
    }
  }
}

void keypair_print( const multimap<table_idx, key_pair> &T_k )
{
  multimap<table_idx, key_pair>::const_iterator it_k; // iterator T_k
  for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k )
  {
    cout << "table_idx k1,k2 : " << it_k->first << " " << it_k->second << endl;
  }
}

#endif /* DOUBLE_ATTACK_CIPHER_H_ */

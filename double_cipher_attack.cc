/*
 * birthday_attack.cc
 *
 *  Created on: 31/03/2013
 *      Author: carneeki
 */

#include <iostream>
#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
#include <map>      // map
#include <ctime>    // time
/*
 * Please read the function prototypes in cryptalg.h for descriptions of each
 * function.
 */
#if DEBUG
#include <iostream>
#include <bitset>
#endif

#ifndef DOUBLE_CIPHER_ATTACK_H_
#include "double_cipher_attack.h"
#endif

using namespace std;

/*
 * Two tables used in this assignment are cstd::multimap because it exhibits
 * O(log n) complexity for find() and insert() operations. This is important for
 * large values of n (such as 2^16).
 *
 * General algorithm breaks from what is believed to be the assignment
 * specification slightly, and the reasons exhibited are as follows:
 *
 * The assignment asks us to generate tables for m_1, m_2 c_1 and c_2. From what
 * we saw in part(2), storing m_1 for every possible k will result in a
 * collision every ~321 attempts. This results in approximately 205 collisions
 * for the entire range of m_1, and just as many collisions for m_2, yielding
 * ~410 collisions.
 *
 * By concatenating m_1 with m_2 we increase our message size to 2^32, and we
 * can treat this as our m_1 value for the purpose of breaking single encryption
 * with collisions, and new m_2 should be old m_2 concatenated with old m_1.
 *
 * This results in a 32 bit input space:
 *
 * Q(H) \approx \sqrt{\frac{\pi}{2} \cdot H}
 *      \approx \sqrt{\frac{\pi}{2} \cdot 2^32}
 *      \approx \sqrt{\pi \cdot 2^31}
 *      \approx \sqrt{2 \cdot \pi 2^30}
 *      \approx 2^15 \cdot \sqrt{2 \cdot \pi}
 *      \approx 82137
 *
 * This means ~82000 keys need to be generated for a 50% collision in the output
 * of E_1(m_1).
 * Given we only need to generate 2^16 keys, the probability of collision can
 * be computed:
 *
 * p(n,H) \approx 1 - e^{-n^2/(2H)}
 *        \approx 1 - e^{-{2^16}^2/(2 * 2^32)}
 *        \approx 1 - \sqrt{e}
 *        \approx 0.393
 *        \approx 39.3% chance of a single collision per algorithm.
 *
 * We are looking at an 80% chance of a single collision across both algorithms,
 * however this is far more appealing than iterating 410 collisions.
 *
 * So:
 *   Step 1: generate sm_1, sm_2 (these are the 16 bit messages).
 *   Step 2: form m_1 as concatenate(sm_1,sm_2)
 *           form m_2 as concatenate(sm_2,sm_1)
 *   Continue assignment as per normal...
 *
 * Generate observations on m_1 (in 2x 16 bit blocks) to produce c_1 (2x blocks)
 * Generate observations on m_2 (in 2x 16 bit blocks) to produce c_2 (2x blocks)
 *
 * The reasoning is that m_1 = (sm_1 sm_2) -> c_1 (sc_1, sc_2)
 *                       m_2 = (sm_2 sm_1) -> c_2 (sc_2, sc_1)
 * As the encryption of blocks are not related to each other. This will reduce
 * the number of collisions.
 *
 * Brute force:
 *   o every key for m_1 and store the cryptogram c_mid (encrypt() ) in T_e
 *   o every key for c_1 and store the cryptogram c_mid (decrypt() ) in T_d
 * Where c_mid is the 'middle' cryptogram we will attack.
 *
 * Now look for cryptograms which are common to T_e and T_d, extracting the keys
 * as a key pair: T_e(c_mid) = k_1, T_d(c_mid) = k_2 and storing in a table of
 * key pairs T_k.
 *
 * Iterate each key pair in T_k, try E_k_2(E_k1_(m_2)) and see if it matches
 * c_2. If not, remove key pair. If match, leave in T_k.
 *
 * Finally, print the remaining key pairs in T_k.
 */

int main( int argc, char* argv[] )
{
  // multimap allows for collisions
  multimap<table_idx, uint16_t> T_e; // all k_1: (c_mid) as index
  multimap<table_idx, uint16_t> T_d; // all k_2: (c_mid) as index
  multimap<table_idx, key_pair> T_k; // all key collisions
  multimap<table_idx, key_pair>::const_iterator it_k; // iterator for shortlist
                                                      // of possible keys

  table_idx tmp_idx; // temporary table index

  observation ob[CRYPTO_ROUNDS];  // observations
  observation mid[CRYPTO_ROUNDS]; // recycle temporary observations memory

  // observations are kept away from main() so as to keep the actual key away
  // from us (ie, cheating prevention).
  srand( time( 0 ) );
  generate_observations( ob );
  encrypt_observations( ob );

  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    cout << " ob[" << i << "] MM MM CC CC : " << ob[i] << endl;
  }

  // brute force all keys
  for( uint16_t i = 0x0001; i < 0xFFFF; i++ )
  {
    uint16_t ekey_lut[FEISTEL_ROUNDS];
    uint16_t dkey_lut[FEISTEL_ROUNDS];

    keysched( 0, i, ekey_lut ); // key schedule for k_i
    keyreverse( ekey_lut, dkey_lut );

    mid[0].m = ob[0].m;
    mid[0].c = ob[0].c;
    mid[1].m = ob[1].m;
    mid[1].c = ob[1].c;

    for( uint8_t j = 0; j < CRYPTO_ROUNDS; j++ )
    {
      // brute force encrypt all m_{0} for k_{0x0001,FFFE}
      _D( cout << "encrypting " << mid[j].m << " key 0x" << setfill( '0' )
               << setw( 4 ) << hex << (long int ) i
      ; );
      feistel( 0, mid[j].m.l, mid[j].m.r, ekey_lut );
      _D( cout << " : " << mid[j].m << " key 0x" << setfill( '0' ) << setw( 4 )
               << hex << (long int ) i << endl
      ; );

      // brute force decrypt all m_{0} for k_{0x0001,FFFE}
      _D( cout << "decrypting " << mid[j].c << " key 0x" << setfill( '0' )
               << setw( 4 ) << hex << (long int ) i
      ; );
      feistel( 0, mid[j].c.r, mid[j].c.l, dkey_lut );
      _D( cout << " : " << mid[j].c << " key 0x" << setfill( '0' ) << setw( 4 )
               << hex << (long int ) i << endl
      ; );

    }
    // store map of middle cryptograms via encrypt()
    tmp_idx.v1 = mid[0].m;
    tmp_idx.v2 = mid[1].m;
    T_e.insert( pair<table_idx, uint16_t>( tmp_idx, i ) );

    // store map of middle cryptograms via decrypt()
    tmp_idx.v1 = mid[0].c;
    tmp_idx.v2 = mid[1].c;
    T_d.insert( pair<table_idx, uint16_t>( tmp_idx, i ) );
  }

  // now look for matches between c_a=E(m_1*k_1) and c_a=D(c_1*k_2)
  // this will be a short list, note k_1 and k_2 of interest
  multimap_intersect( T_e, T_d, T_k );

  _D( keypair_print( T_k )
  ; );

  // use the shortlist of k_1 and k_2 to do a micro-brute force
  // ie: test that these keys match produce the same double cryptogram
  // as our observations
  for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k )
  {
    uint16_t s_key[CRYPTO_ROUNDS];
    uint16_t ekey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS];

    s_key[0] = it_k->second.k1;
    s_key[1] = it_k->second.k2;

    for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    {
      keysched( 0, s_key[i], ekey_lut[i] );
      mid[i].m = ob[i].m;
      mid[i].c = ob[i].m;
    }

    // need the same loop a second time because key generation is not
    // complete until all loops are completed above
    for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    {
      multi_feistel( mid[i].c.l, mid[i].c.r, ekey_lut );

      if( i == CRYPTO_ROUNDS - 1 )
      {
        cout << "Trying keys k1,k2: " << "0x" << setw( 4 ) << setfill( '0' )
             << hex << (long int) s_key[0] << " " << "0x" << setw( 4 )
             << setfill( '0' ) << hex << (long int) s_key[1] << " : ";
      }

      // compare cryptograms against observations
      if( ( mid[0].c == ob[0].c ) && ( mid[1].c == ob[1].c ) )
      {
        cout << "MATCH!" << endl;
      }
      else
      {
        cout << endl;
      }
    }
  }

  return 0;
}

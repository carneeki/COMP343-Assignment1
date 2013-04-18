/*
 * double_cipher_attack.cc
 *
 *  Created on: 13/04/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */
using namespace std;

#include "globals.h"
#include "helpers.h"
#include "double_cryptalg.h"
#include "double_cipher_attack.h"

/*
 * Two tables used in this assignment are cstd::multimap because it exhibits
 * O(log n) complexity for find() and insert() operations. This is important for
 * large values of n (such as 2^16).
 *
 * This algorithm breaks from what is believed to be the assignment
 * specification slightly, and the main reason is due to an observation found in
 * the birthday attack of part 2.
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
 *
 * Substitute in n = 2^16, H=2^32 :
 *        \approx 1 - e^{-{2^16}^2/(2 * 2^32)}
 *        \approx 1 - \sqrt{e}
 *        \approx 0.393
 *        \approx 39.3% chance of a single collision per algorithm.
 *
 * Given we are running two tables the likelihood of an unwanted collision goes
 * increase somewhat, however, this would be a single unwanted collision.
 *
 * Anticipated memory usage:
 *  #num_of_keys * num_bytes * num_tables
 *  (2^16)       * (4+2)     * 2
 *  = 7.8MB
 *                  ^ ^--- 2 bytes for key value
 *                  +----- 4 bytes for 2^32 index
 *
 * Actual memory usage profiled using pmap -x <pid> showed 6380KB
 * in addition to stack (132KB) and C libraries (12156kb).
 *
 * So:
 *   Step 1: generate sm_1, sm_2 (these are the original 16 bit messages).
 *   Step 2: form m_1 as concatenate(sm_1,sm_2)
 *           form m_2 as concatenate(sm_2,sm_1)
 *   Continue assignment as per normal...
 *
 * Generate observations on m_1 (in 2x 16 bit blocks) to produce c_1 (2x blocks)
 * Generate observations on m_2 (in 2x 16 bit blocks) to produce c_2 (2x blocks)
 *
 * The reasoning is that m_1 = (sm_1, sm_2) -> c_1 (sc_1, sc_2)
 *                       m_2 = (sm_2, sm_1) -> c_2 (sc_2, sc_1)
 * This should be OK because sm_1 -> sc_1 and sm_2 -> sc_2 (in ECB mode, the
 * cryptograms are not related to each other).
 *
 * Brute force:
 *   o every key for E_1(m_1) and store the cryptogram in T_e
 *   o every key for D_2(c_1) and store the cryptogram in T_d
 *
 * Look for the intersection of the indexes of T_e and T_d (that is, cryptograms
 * which are common in both T_e and T_d). Extracting the keys and store in a
 * table of key pairs T_k.
 *
 * Iterate each key pair in T_k, and try E_k_2(E_k1_(m_2)) and see if it matches
 * c_2. If not, remove key pair. If match, leave in T_k.
 *
 * Finally, print the remaining key pairs in T_k.
 */

int main( int argc, char* argv[] )
{
  // multimap allows for collisions
  // although, in theory there should few if any collisions
  // in the expanded 2^32 space
  multimap<table_idx, uint16_t> T_e; // all k_1: (c_mid) as index
  multimap<table_idx, uint16_t> T_d; // all k_2: (c_mid) as index
  multimap<table_idx, key_pair> T_k; // all key collisions

  multimap<table_idx, key_pair>::const_iterator it_k; // iterator for shortlist
                                                      // of possible keys

  table_idx tmp_idx;              // temporary table index

  observation ob[CRYPTO_ROUNDS];  // observations
  observation mid[CRYPTO_ROUNDS]; // middle cryptograms
                                  // use the m variable to represent E_1(m1)
                                  // use the c variable to represent D_2(c1)

  // initialize random seed
  srand( time( 0 ) );

  // observations contain ONLY the message and cryptogram... it prevents main()
  // from cheating and looking at the answer!
  generate_observations( ob );
  encrypt_observations( ob );

  // print the original observations
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    cout << " ob[" << i << "] MM MM CC CC : " << ob[i] << endl;

  // brute force all keys
  for( uint16_t i = 0x0000; i < 0xFFFF; i++ )
  {
    uint16_t ekey_lut[FEISTEL_ROUNDS];
    uint16_t dkey_lut[FEISTEL_ROUNDS];

    keysched( 0, i, ekey_lut ); // key schedule for k_i
    keyreverse( ekey_lut, dkey_lut );

    // single round encrypt
    for( uint8_t j = 0; j < CRYPTO_ROUNDS; j++ )
    {
      // copy message and cryptograms from observation
      mid[j].m = ob[j].m;
      mid[j].c = ob[j].c;
      // brute force encrypt all m_{0} for k_{0x0001,FFFE}
      feistel( 0, mid[j].m.l, mid[j].m.r, ekey_lut );

      // brute force decrypt all m_{0} for k_{0x0001,FFFE}
      feistel( 0, mid[j].c.r, mid[j].c.l, dkey_lut );
    } /* for( uint8_t j = 0; j < CRYPTO_ROUNDS; j++ ) */

    // store map of middle cryptograms from encrypting m1:
    tmp_idx.v1 = mid[0].m;
    tmp_idx.v2 = mid[1].m;
    T_e.insert( pair<table_idx, uint16_t>( tmp_idx, i ) );

    // store map of middle cryptograms from decrypting c1:
    tmp_idx.v1 = mid[0].c;
    tmp_idx.v2 = mid[1].c;
    T_d.insert( pair<table_idx, uint16_t>( tmp_idx, i ) );
  } /* for( uint16_t i = 0x0000; i < 0xFFFF; i++ ) */

  // create a short list of k_1 and k_2 where the cryptograms intersect
  // from E_1(m_1) and D_2(c_2)
  multimap_intersect( T_e, T_d, T_k );

  // print the intersection
  _D( keypair_print( T_k ); );


  shortlist_attack(T_k, ob);

  return 0;
} /* main() */

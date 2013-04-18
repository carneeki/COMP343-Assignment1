/*
 * double_cipher_attack.h
 *  Created on: 13/04/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */

#ifndef DOUBLE_CIPHER_ATTACK_H_
#define DOUBLE_CIPHER_ATTACK_H_

#ifndef GLOBALS_H_
#include "globals.h"
#endif

#ifndef HELPERS_H_
#include "helpers.h"
#endif

using namespace std;

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
    } /* operator== */

    friend ostream& operator<<( ostream &os, const observation &ob )
    {
      os << ob.m << " " << ob.c;
      return os;
    } /* operator<< */
}; /* struct observation */

/**
 * table_idx
 * Index for multimap tables, 32 bits in length. Can contain a 32 bit cryptogram
 * or message - designed for holding the middle value for meet in the middle
 * attack.
 */
struct table_idx
{
    lr_pair v1; // cryptogram 1
    lr_pair v2; // cryptogram 2

    bool operator==( const table_idx &other ) const
    {
      return ( ( v1 == other.v1 ) && ( v2 == other.v2 ) );
    } /* operator== */

    bool operator<( const table_idx &other ) const
    {
      if( v1 < other.v1 )
        return true;
      else if( ( v1 == other.v1 ) && ( v2 < other.v2 ) )
        return true;
      else
        return false;
    } /* operator< */

    friend ostream& operator<<( ostream &os, const table_idx &tbl )
    {
      os << tbl.v1 << " " << tbl.v2;
      return os;
    } /* operator<< */
}; /* struct table_idx */

/**
 * Encrypt observations using unknown random keys from known input messages
 * @param ob
 */
void encrypt_observations( observation (&ob)[CRYPTO_ROUNDS] );

/**
 * Generate two random observations and pass them back to main.
 */
void generate_observations( observation (&ob)[CRYPTO_ROUNDS] );

/**
 * keypair_print
 * Print a listing of keypairs (useful for debugging).
 * @param T_k Table containing key pairs k1, k2 of intersection with middle
 *            cryptogram as index.
 */
void keypair_print( const multimap<table_idx, key_pair> &T_k );

/**
 * main()
 * Main program
 * @param argc argument count
 * @param argv argument values
 * @return
 */
int main( int argc, char* argv[] );

/**
 * multimap_intersect()
 * Return the logical intersection of two multimaps.
 * @param T_e Table containing keys and middle cryptograms from running
 *            encryption operations (cryptogram as index).
 * @param T_d Table containing keys and middle cryptograms from running
 *            decryption operations (cryptogram as index).
 * @param T_k Table containing key pairs k1, k2 of intersection with middle
 *            cryptogram as index.
 */
void multimap_intersect( const multimap<table_idx, uint16_t> &T_e,
                         const multimap<table_idx, uint16_t> &T_d,
                         multimap<table_idx, key_pair> &T_k );

/**
 * shortlist_attack
 * Perform a brute force attack on a given list of key pairs and compare the
 * output with the original observations. This will print keys where the
 * cryptogram c_1 = E_2( E_1(m_1) ) and c_2 = E_2( E_1(m_2) ).
 * @param T_k Table containing key pairs k1, k2 of intersection with middle
 *            cryptogram as index.
 * @param ob
 */
void shortlist_attack(const multimap<table_idx, key_pair> &T_k,
                      const observation (&ob)[CRYPTO_ROUNDS]);

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
// Function definitions below this point.
//
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

void encrypt_observations( observation (&ob)[CRYPTO_ROUNDS] )
{
  uint16_t s_key[CRYPTO_ROUNDS];
  uint16_t ekey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS];

  // create keys and generate key schedule
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    // create random key
    s_key[i] = rand();

    // set a known key for debugging
    _D(
      s_key[0] = 0xFEED;
      s_key[1] = 0xCAFE;
    );

    // print a message telling us what the keys are
    cout << "k[" << i << "]=0x"
         << setw(4) << setfill('0') << hex << s_key[i]
         << " ( ssh! don't tell main() our little secret! )"
         << endl;

    // generate key schedule
    keysched( 0, s_key[i], ekey_lut[i] );
  } /* for( int i = 0; i < CRYPTO_ROUNDS; i++ ) */

  // call multi_feistel to create observations
  // must be separate loop to above so that
  // keys are properly generated
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    multi_feistel( ob[i].c.l, ob[i].c.r, ekey_lut );
} /* encrypt_observations() */

void generate_observations( observation (&ob)[CRYPTO_ROUNDS] )
{
  for( int i = 0; i < CRYPTO_ROUNDS; i++ )
  {
    ob[i].m.l = rand();
    ob[i].m.r = rand();

    // debug code, insert "ADAM" as test data
    _D(
      ob[0].m.l = 0x41;
      ob[0].m.r = 0x44;
      ob[1].m.l = 0x41;
      ob[1].m.r = 0x4d;
    ); /* _D() */

    // copy the message to the cryptogram space so multi_feistel() does not
    // clobber them in the pass by reference
    ob[i].c = ob[i].m;
  } /* for( int i = 0; i < CRYPTO_ROUNDS; i++ ) */
} /* generate_observations() */

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
      // technically this match should ALWAYS be true
      if( it_e->first == it_d->first )
      {
        kp.k1 = it_e->second;
        kp.k2 = it_d->second;
        T_k.insert( std::pair<table_idx, key_pair>( it_e->first, kp ) );
      } /* if( it_e->first == it_d->first ) */
    } /* inner for() loop */
  } /* for( it_e = T_e.begin(); it_e != T_e.end(); ++it_e ) */
} /* multimap_intersect() */

void keypair_print( const multimap<table_idx, key_pair> &T_k )
{
  multimap<table_idx, key_pair>::const_iterator it_k; // iterator T_k
  for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k )
  {
    cout << "table_idx k1,k2 : " << it_k->first << " " << it_k->second << endl;
  } /* for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k ) */
} /* void keypair_print() */

void shortlist_attack(const multimap<table_idx, key_pair> &T_k,
                      const observation (&ob)[CRYPTO_ROUNDS])
{
  multimap<table_idx, key_pair>::const_iterator it_k; // iterator T_k
  observation cf[CRYPTO_ROUNDS]; // confirm the observation?

  // use the shortlist of k_1 and k_2 to do a micro-brute force
  // ie: test that these keys match produce the same double cryptogram
  // as our observations
  for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k )
  {
    uint16_t s_key[CRYPTO_ROUNDS];
    uint16_t ekey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS];

    // copy key to array for iteration
    s_key[0] = it_k->second.k1;
    s_key[1] = it_k->second.k2;

    // key schedule generation is not complete
    // until loop is completed entirely.
    // do not run multi_feistel() until then!
    for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    {
      keysched( 0, s_key[i], ekey_lut[i] );

      // copy observation to our confirmation variable
      cf[i].m = ob[i].m;
      cf[i].c = ob[i].m;
    }

    // generate test results
    for( int i = 0; i < CRYPTO_ROUNDS; i++ )
    {
      multi_feistel( cf[i].c.l, cf[i].c.r, ekey_lut );

      // print only after running last multi_feistel
      if( i == CRYPTO_ROUNDS - 1 )
      {
        cout << "Trying keys k1,k2: " << "0x" << setw( 4 ) << setfill( '0' )
             << hex << (long int) s_key[0] << "," << "0x" << setw( 4 )
             << setfill( '0' ) << hex << (long int) s_key[1] << " : ";

        // compare cryptograms against observations
        if( ( cf[0].c == ob[0].c ) && ( cf[1].c == ob[1].c ) )
        {
          cout << "MATCH!" << endl;
        }
        else
        {
          cout << endl;
        } // if() compare cryptograms against observations */
      } /* if() print only after running last multi_feistel */
    } /* for( int i = 0; i < CRYPTO_ROUNDS; i++ ) */
  } /* for( it_k = T_k.begin(); it_k != T_k.end(); ++it_k ) */
} /* shortlist_attack() */

#endif /* DOUBLE_CIPHER_ATTACK_H_ */

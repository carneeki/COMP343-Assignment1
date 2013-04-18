/*
 * birthday_attack.cc
 *  Created on: 31/03/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */
using namespace std;
#include "globals.h"
#include "helpers.h"
#include "birthday_attack.h"

/* Iterate every possible message (2^16) inside an iteration of every possible
 * chaining variable (2^16). This gives a total of 2^32 combinations, a 32 bit
 * input.
 *
 * Our output only allows for 2^16 combinations.
 *
 * (total combinations * input size) / (8*1024) = WORST CASE memory use.
 *
 *                       (2^16 * 32) / (8*1024) = 256kB of memory.
 *
 * 256kB is WORST CASE memory use.
 *
 * If we apply the birthday paradox over the hash space, we can use the follow
 * function to predict the number of hashes to generate before finding a
 * collision (\LaTeX formatting):
 *
 * Q(H) \approx \sqrt{\frac{\pi}{2} \cdot H}
 *
 * Where H is the number of outputs.
 * Substitute H = 2^16:
 *
 * Q(2^16) \approx \sqrt{\frac{\pi}{2} \cdot 2^16}
 *         \approx 128\sqrt{2\pi}
 *         \approx 321
 *
 * This number concurs with testing in debug mode (compile with flag -DDEBUG=1)
 *
 * (avg combinations * input size) = AVERAGE CASE memory use
 *                       ~321 * 32 = ~10272 bits
 *                                 = ~1284 bytes
 *
 * Therefore AVERAGE CASE memory use is approximately 1284 bytes.
 */
int main( int argc, char* argv[] )
{

  _D( fprintf(stdout, "main(): starting\n"); )

  /**
   * Store hash as h=(m,c) where m = message and c = chaining variable
   */
  map<uint16_t, input_pair> hash_map;
  map<uint16_t, input_pair>::iterator iter;
  input_pair hash_input;

  uint16_t hash;  // combined hash

  uint8_t l;  // left message
  uint8_t r;  // right message

  uint16_t key_lut[FEISTEL_ROUNDS]; // key lookup table

  srand( time( 0 ) ); // initialize random seed.

  // keep looping until a return() call breaks execution
  //     * or we run out of memory, and swap space
  while( true )
  {
    // clear hash from previous iteration
    hash = 0;

    hash_input.c = rand();
    l = rand();
    r = rand();

    // generate key schedule for new key
    keysched( 0, hash_input.c, key_lut );


    hash_input.m = l; // combine left and right parts of message (2*8bits)
    hash_input.m = ( hash_input.m << 8 ) | r;

    // create the hash
    feistel( 0, l, r, key_lut );

    // combine left and right parts
    hash = l;
    hash = ( hash << 8 ) | r;

    _D( fprintf(stderr, "%04x=(%04x,%04x)\n", hash, hash_input.c, hash_input.m); )

    // check for a collision:
    iter = hash_map.find( hash );
    if( iter != hash_map.end() )
    {
      // collision detected, print output then exit
      fprintf( stdout, "0x%04x\t0x%04x\n0x%04x\t0x%04x\ncollision\n",
               iter->second.m, iter->second.c, hash_input.m, hash_input.c );

      _D(
          fprintf(stderr, "0x%04x\t0x%04x\n0x%04x\t0x%04x\ncollision on hash:0x%04x\n", iter->second.m, iter->second.c, hash_input.m, hash_input.c, hash);
          fprintf(stderr, "size of hash_map %ld\n", hash_map.size());
      );

      // exit
      return 0;
    } /* if( iter != hash_map.end() ) */

    // no collision: store the node in the hash map
    hash_map[hash] = hash_input;
  } /* while( true ) */

  // technically this code should be unreachable, but if it does, print
  // to error output and return a non-zero
  fprintf( stderr, "No collisions found\n" );
  return 1;
} /* main() */

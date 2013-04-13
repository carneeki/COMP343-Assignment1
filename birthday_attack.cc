/*
 * cryptalg.cc
 *
 *  Created on: 31/03/2013
 *      Author: carneeki
 */

#include <iostream>
#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
#include <exception>
/*
 * Please read the function prototypes in cryptalg.h for descriptions of each
 * function.
 */
#include "cryptalg.h"
#include "helpers.h"
#include "trie.h"

#if DEBUG
#include <iostream>
#include <bitset>
#endif
using namespace std;

/* Iterate every possible message (2^16) inside an iteration of every possible
 * chaining variable (2^16). This gives a total of 2^32 combinations.
 *
 * Our output only allows for 2^16 combinations, so it is very likely that there
 * will be collisions within just the one key value, as such, 2^16 slots of 32
 * bits should be maximum memory requirement.
 *
 * 2^16 * 32 / (8*1024) = 256kB of memory.
 *
 * If we apply the birthday paradox over the hash space, we can use the follow
 * PI function to predict the probability of a collision (formatting in \LaTeX)
 * for a smaller number of bits (x)
 *
 * 1- \left(\Pi_{n=0}^{2^x} \frac{(2^16-n)}{(2^16)} \right)
 *
 * When we substitute x = 8, there is a 40% (approx) chance there will be a
 * collision. Substituting x = 9 yields an 86.6% chance. and x = 10 results in
 * a 99.9997% chance of a match.
 *
 * If using x = 10, this means that we need hold only 2^10 slots of 32 bits:
 *
 * 2^10 * 32 / (8*1024) = 4kb of memory with an almost certain chance of a
 * collision.
 *
 * generate a random message
 * hash
 * check for collision, else store in database
 */
int main(int argc, char* argv[])
{

  _D(fprintf(stdout, "main(): starting\n");)

  Trie db = Trie();

  uint8_t hash_l; // left part of hash
  uint8_t hash_r; // right part of hash
  uint16_t hash;  // combined hash
  uint16_t m; // message

  // need to start looking through 2^32 places. Almost 4 billion.
  // (actually - worst case will be (2^16)+1 because in a VERY worst case,
  // the first 2^16 cases will not collide, but on the 2^16 +1 case, we MUST have
  // a collision by way of the entire hash address space being fully exhausted.

  // BUT incrementing chain variable (key schedule) is expensive by comparison
  // to incrementing an input message - let's iterate all values (messages) for
  // one chain variable and only then increment. We might get lucky and have a
  // collision before generating a new key.
  for (uint16_t c = 0; c < 0xFFFF; c++)
  {
    // generate a new chaining variable
    starting_key = c;
    keysched(0, key_lut);

    for (uint8_t l = 0; l < 0xFF; l++)
    {
      // generate new left message
      for (uint8_t r = 0; r < 0xFF; r++)
      {
        Node* node;      // node to store message and chaining variable
        node = new Node();
        hash = 0;

        m = l; // combine left and right parts of message (2*8bits)
        m = (m << 8) | r;

        // store message and chaining variables in a node
        node->set(&m, &c);

        // create the hash
        hash_l = l; // need to copy l and r, encrypt() in prev round
        hash_r = r; // will have otherwise overwritten (by reference)

        encrypt(0, hash_l, hash_r);

        // combine left and right parts
        hash = hash_l;
        hash = (hash << 8) | hash_r;


        fprintf(stdout, "%04x=(%04x,%04x)\n", hash,c,m);

        // store the node in the trie
        try
        {
          db.add(hash, node);
        }
        catch (const HashCollisionException& e)
        {
          fprintf(stdout, "%s\n", e.what());
          exit(EXIT_SUCCESS);
        }
      }
    }
  }

  fprintf(stdout, "No collisions found\n");
  return 0;
}

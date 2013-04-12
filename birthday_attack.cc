/*
 * cryptalg.cc
 *
 *  Created on: 31/03/2013
 *      Author: carneeki
 */

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

int main(int argc, char* argv[])
{

  _D(fprintf(stdout, "main(): starting\n");)

  Trie db = Trie();

  uint16_t tmp_hash;
  // need to start looking through 2^32 places. Almost 4 billion.
  // (actually - worst case will be (2^16)+1 because in a VERY worst case,
  // the first 2^16 cases will not collide, but on the 2^16 +1 case, we MUST have
  // a collision by way of the entire hash address space being fully exhausted.

  // BUT incrementing chain variable (key schedule) is expensive by comparison
  // to incrementing an input message - let's iterate all values (messages) for
  // one chain variable and only then increment. We might get lucky and have a
  // collision before generating a new key.
  for (uint16_t c = 0; c < (2 ^ (sizeof(uint16_t) * 8)); c++)
  {
    // generate a new chaining variable
    starting_key = c;
    keysched(0, key_lut);

    for (uint8_t l = 0; l < (2 ^ (sizeof(uint16_t) * 8)); l++)
    {
      // generate new left message
      for (uint8_t r = 0; r < (2 ^ (sizeof(uint16_t) * 8)); r++)
      {
        uint32_t tmp_msg = l;
        tmp_msg = (tmp_msg << 8) | r;

        // generate new right message
        // generate a new node to store the message
        Node* node = new Node();
        node->set(tmp_msg, c);
        uint8_t tmp_l = l; // need to copy l and r, encrypt() in prev round
        uint8_t tmp_r = r; // will have otherwise overwritten (by reference)

        encrypt(0, tmp_l, tmp_r);

        // combine l (left 8), r (right 8) => this is the hash
        tmp_hash = l;
        tmp_hash = (tmp_hash << 8) | r;

        try
        {
          db.add(tmp_hash, node);
        } catch (const HashCollisionException& e)
        {
          fprintf(stdout, "%s\n", e.what());
        }
      }
    }
  }
  /* generate a random key
   * generate a random message
   * hash
   * check for collision, else store in database
   */

  fprintf(stdout, "byebye\n");
  return 0;
}

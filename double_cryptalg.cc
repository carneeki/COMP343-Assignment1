/*
 * double_cryptalg.cc
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

#include "cryptalg.h"
#include "helpers.h"

using namespace std;

struct key32
{
    uint16_t k1; // key 1
    uint16_t k2; // key 2
};

struct observation
{
    uint16_t m; // message
    uint16_t c; // cryptogram
};

int main(int argc, char* argv[] )
{
  map<uint16_t, uint16_t> m1_observe; // msg as index, cryptogram as val
  map<uint16_t, uint16_t> m2_observe; // msg as index, cryptogram as val
  map<uint16_t, uint16_t> m1_rainbow; // cryptogram as index, msg as val
  map<uint16_t, uint16_t> m2_rainbow; // cryptogram as index, msg as val

  map<uint16_t, uint16_t>::iterator m1_o_iter; // observe iterator
  map<uint16_t, uint16_t>::iterator m2_o_iter; // observe iterator
  map<uint16_t, uint16_t>::iterator m1_r_iter; // rainbow iterator
  map<uint16_t, uint16_t>::iterator m2_r_iter; // rainbow iterator

  // accept 16 bit message
  uint16_t buf;

  // accept 32 bit key
  key32 key;

  // observation 1 & 2:
  observation observ1;
  observation observ1;


  //
  for(int i=0; i < (2^16); i++)
  {
    //
  }
  srand(time(0));

  return 0;
}

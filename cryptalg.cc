/*
 * cryptalg.cc
 *
 *  Created on: 31/03/2013
 *      Author: carneeki
 */

#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
/*
 * Please read the function prototypes in cryptalg.h for descriptions of each
 * function.
 */
#include "cryptalg.h"
#include "helpers.h"

#if DEBUG
#include <iostream>
#include <bitset>
#endif

int main(int argc, char* argv[])
{

  _D(fprintf(stdout, "main(): starting\n");)

  fstream in;   // input file stream
  ofstream out; // output file stream

  uint8_t buf[BLOCK_SIZE]; // buffer to put input block
  _D(unsigned long cur_block; // current buffer iterator
      cur_block = 0;)

  mode = _init(argc, argv, in, out);

  // while having the same while() loop duplicates some code, it results in
  // fewer JMP opcodes in the assembly when compiled
  if (mode)
  {
    // encrypt
    while (in.read((char*) buf, BLOCK_SIZE))
    {
      _D(
          fprintf(stderr, "********** main(): in  block[0x%04lx] *******************************************\n",cur_block); fprintf(stderr, "main(): in  block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]); bitset<8> l_in(buf[0]); bitset<8> r_in(buf[1]); cout << " " << l_in << " : " << r_in << endl;)

      encrypt(0, buf[0], buf[1]);

      _D(
          fprintf(stderr, "main(): out block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]); bitset<8> l_out(buf[0]); bitset<8> r_out(buf[1]); cout << " " << l_out << " : " << r_out << endl; cur_block++;)

      out.write((char*) buf, BLOCK_SIZE);
    }
  }
  else
  {
    // decrypt
    keyreverse();

    while (in.read((char*) buf, BLOCK_SIZE))
    {
      _D(
          fprintf(stderr, "********** main(): in  block[0x%04lx] *******************************************\n",cur_block); fprintf(stderr, "main(): in  block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]); bitset<8> l_in(buf[0]); bitset<8> r_in(buf[1]); cout << " " << l_in << " : " << r_in << endl;)

      decrypt(0, buf[0], buf[1]);

      _D(
          fprintf(stderr, "main(): out block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]); bitset<8> l_out(buf[0]); bitset<8> r_out(buf[1]); cout << " " << l_out << " : " << r_out << endl; cur_block++;)

      out.write((char*) buf, BLOCK_SIZE);
    }
  }

  in.close();
  out.close();

  _D(fprintf(stdout, "main(): ending\n");)
  return 0;
}

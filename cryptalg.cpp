/*
 * cryptalg.cpp
 *
 *  Created on: 31/03/2013
 *      Author: carneeki
 */

#include <stdio.h>
#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <fstream>  // ifstream
#include "cryptalg.h"

int decrypt(fstream& infile, ofstream& outfile, uint16_t key)
{

}

int encrypt(fstream& infile, ofstream& outfile, uint16_t key)
{

}

void feistel_round(uint8_t round_num, uint8_t *left, uint8_t *right)
{

}

void help(char* argv[])
{
  fprintf(stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0]);
}

void keysched(uint8_t round, uint8_t *key_lut)
{
  // handle default case of max_rounds + 1
  if (round > FEISTEL_ROUNDS)
  {
    return;
  }
  else if (round == 0) // K0 = bits 7..0
  {
    key_lut[round] = _lo8(starting_key);
  }
  else if (round == 1) // K1 = bits 15..8
  {
    key_lut[round] = _hi8(starting_key);
  }
  else
  {
    // Ki = ROTL^3(Ki-1) xor ROTL^5(Ki-2) | i = 2..7
    key_lut[round] = rol(3, key_lut[round - 1]) ^ rol(5, key_lut[round - 2]);
  }

  // call recursively
  keysched(round + 1, key_lut);
}

int main(int argc, char* argv[])
{
  char *strinfile;    // relative path to input file
  char *stroutfile;   // relative path to output file
  uint16_t key;        // key, eg: 0xCAFE
  char *oper;           // operation: E = encrypt / D = decrypt
//  fstream infile;      // input file stream  // TODO: declare me
//  ofstream outfile;    // output file stream // TODO: and initialize separately
  unsigned long inlen; // input file size

  // Show a friendly help message
  if (argc != 5)
  {
    help(argv);
    return 1;
  }

  strinfile = argv[1];
  stroutfile = argv[2];
  key = (uint16_t) strtoul(argv[3], NULL, 0);
  oper = argv[4][0];

  fstream infile(strinfile,
      ios::binary | ios::in | ios::out | ios::ate);
  ofstream outfile(stroutfile, ios::binary | ios::out | ios::trunc);

  if (!infile)
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strinfile);
    return 1;
  }
  if (!outfile)
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strinfile);
    return 1;
  }

  if (infile.good())
  {
    inlen = infile.tellg();
    if (inlen == 0)
    {
      // empty file
      return 0;
    }
  }
}

uint8_t permute(uint8_t *hi, uint8_t low)
{

}

uint8_t sbox(uint8_t input)
{
  uint8_t the_sbox[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };
  return the_sbox[input];
}

uint8_t rol(uint8_t shift, const uint8_t input)
{

}
uint16_t rol(uint8_t shift, const uint16_t input)
{

}

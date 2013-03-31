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

int decrypt(fstream& in, ofstream& out, uint16_t key)
{
#ifdef DEBUG
  fprintf(stdout, "decrypt(): starting\n");
#endif
  return 0;
}

int encrypt(fstream& in, ofstream& out, uint16_t key)
{
#ifdef DEBUG
  fprintf(stdout, "encrypt(): starting\n");
#endif
  return 0;
}

void feistel_round(uint8_t round_num, uint8_t *left, uint8_t *right)
{
#ifdef DEBUG
  fprintf(stdout, "feistel_round(): starting\n");
#endif
  return;
}

void help(char* argv[])
{
  fprintf(stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0]);
  return;
}

void keysched(uint8_t round, uint8_t *key_lut)
{
#ifdef DEBUG
  fprintf(stdout, "keysched(%d): starting ", round);
#endif

  // check we are not generating too many keys
  if (round == FEISTEL_ROUNDS)
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

#ifdef DEBUG
  fprintf(stdout, "key_lut[%d] = 0x%02x\n", round, key_lut[round]);
#endif

  // call recursively, but not too many times
  if (round + 1 < FEISTEL_ROUNDS)
  {
    keysched(round + 1, key_lut);
  }
  return;
}

int main(int argc, char* argv[])
{
#ifdef DEBUG
  fprintf(stdout, "main(): starting\n");
#endif
  fstream in;   // input file stream
  ofstream out; // output file stream

  if (_init(argc, argv, in, out))
  {
    // encrypt
    return encrypt(in, out, starting_key);
  }
  else
  {
    // decrypt
    return decrypt(in, out, starting_key);
  }
}

uint8_t permute(uint8_t *hi, uint8_t *lo)
{
#ifdef DEBUG
  fprintf(stdout, "permute(): starting\n");
#endif

  // combine nibbles to get byte
  uint8_t combined = (*hi | *lo);

  // rotate left by 2
  return rol(2, combined);
}

uint8_t sbox(uint8_t input)
{
  uint8_t the_sbox[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };
  return the_sbox[input];
}

uint8_t rol(uint8_t shift, const uint8_t input)
{
  return (input << shift) | (input >> (sizeof(input) * 8 - shift));
}

uint8_t ror(uint8_t shift, const uint8_t input)
{
  return (input >> shift) | (input << (sizeof(input) * 8 - shift));
}

uint8_t _hin(uint16_t input, uint8_t bits)
{
  return ((input >> bits));
}

uint8_t _lon(uint16_t input, uint8_t bits)
{
  return (input & ((1 << bits) - 1));
}

uint8_t _hi8(uint16_t input)
{
  return _hin(input, 8);
}

uint8_t _lo8(uint16_t input)
{
  return _lon(input, 8);
}

uint8_t _hi4(uint8_t input)
{
  return _hin(input, 4);
}

uint8_t _lo4(uint8_t input)
{
  return _lon(input, 4);
}

bool _init(int argc, char* argv[], fstream &in, ofstream &out)
{
#ifdef DEBUG
  fprintf(stdout, "_init(): starting\n");
#endif
  // Show a friendly help message
  if (argc != 5)
  {
    help(argv);
  }

  char *strin;         // relative path to input file
  char *strout;        // relative path to output file
  char *oper;          // operation: E = encrypt / D = decrypt
  bool retval;         // return value, 0 for decrypt, 1 for encrypt

  strin = argv[1];
  strout = argv[2];
  starting_key = (uint16_t) strtoul(argv[3], NULL, 0);
  oper = argv[4];

  in.open(strin, ios::binary | ios::in | ios::out | ios::ate);
  out.open(strout, ios::binary | ios::out | ios::trunc);

  // do sanity checks on files now
  if (!in.good())
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strin);
    exit(EXIT_FAILURE);
  }
  if (!out.good())
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strin);
    exit(EXIT_FAILURE);
  }

  if (in.tellg() == 0)
  {
    // empty file
    fprintf(stderr, "FATAL: input file %s is empty. Quitting.\n", strin);
    exit(EXIT_FAILURE);
  }

  // assume input files are sane
  if ((*oper == 'E') || (*oper == 'e'))
  {
    retval = 1;
  }
  else if ((*oper == 'D') || (*oper == 'd'))
  {
    retval = 0;
  }
  else
  {
    help(argv);
    exit(EXIT_FAILURE);
  }

#ifdef DEBUG
  fprintf(stdout, "_init(): in: %s out: %s key: 0x%04x rounds: %d mode: %s \n",
      strin, strout, starting_key, FEISTEL_ROUNDS, oper);
#endif

  keysched(0, key_lut);

  return retval;
}

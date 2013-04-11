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

#if DEBUG
#include <iostream>
#include <bitset>
#endif

void decrypt(uint8_t round, uint8_t &Li, uint8_t &Ri)
{
  _D(fprintf(stdout, "decrypt(%d): starting\n", round);)

  // check we are not doing too many rounds
  if (round == FEISTEL_ROUNDS)
  {
    return;
  }

  uint8_t next; // Li_Next or Ri_Next (depends on encrypt vs decrypt)
  uint8_t tmp;  // temporary scratch space

  /* Decrypt:
   * F-BOX :: START
   * 1. Li XOR Ki
   * 2. sbox hi and lo nibble
   * 3. combine nibbles and permute
   * F-BOX :: END
   *
   * 4. LiNext = Ri XOR permute
   * 5. RiNext = Li
   * 6. Send to next Feistel round
   */

  // F-BOX :: START
  // 1. Li XOR Ki
  tmp = Li ^ key_lut[round];

  // 2. sbox lo and hi nibble
  // 3. combine nibbles and permute
  tmp = permute(sbox(_hi4(tmp)), sbox(_lo4(tmp)));
  // F-BOX :: END

  // 4. LiNext = Ri XOR permute
  // 5. RiNext = Li... Just pass Li
  next = Ri ^ tmp;

  // call recursively, but not too many times
  if (round + 1 < FEISTEL_ROUNDS)
  {
    decrypt(round + 1, next, Li);
  }

  // update references for 'return' to parent
  Ri = Li;
  Li = next;
}

void encrypt(uint8_t round, uint8_t &Li, uint8_t &Ri)
{
  _D(fprintf(stdout, "encrypt(%d): starting\n", round);)

  // check we are not doing too many rounds
  if (round == FEISTEL_ROUNDS)
  {
    return;
  }

  uint8_t next; // Li_Next or Ri_Next (depends on encrypt vs decrypt)
  uint8_t tmp;  // temporary scratch space

  /* Encrypt:
   * F-BOX :: START
   * 1. Ri XOR Ki
   * 2. sbox hi and lo nibble
   * 3. combine nibbles and permute
   * F-BOX :: END
   *
   * 4. RiNext = Li XOR permute
   * 5. LiNext = Ri
   * 6. Send to next Feistel round
   */

  // F-BOX :: START
  // 1. Ri XOR Ki
  tmp = (Ri ^ key_lut[round]);

  _D(
      fprintf(stdout, "encrypt(%d): Ri XOR Ki = 0x%02x     ^ 0x%02x\n", round,Ri, key_lut[round]); bitset<8> bRi(Ri); bitset<8> bKi(key_lut[round]); bitset<8> btmp(tmp); cout << "feistel_round() : Ri ^ Ki   = " << bRi << " ^ " << bKi << "=" << btmp << endl;);

  // 2. sbox lo and hi nibble
  // 3. combine nibbles and permute
  tmp = permute(sbox(_hi4(tmp)), sbox(_lo4(tmp)));
  // F-BOX :: END

  // 4. RiNext = Li XOR permute
  // 5. LiNext = Ri... Just pass Ri
  next = Li ^ tmp;

  // call recursively, but not too many times
  if (round + 1 < FEISTEL_ROUNDS)
  {
    encrypt(round + 1, Ri, next);
  }
  // update 'return' references
  Li = Ri;
  Ri = next;
}

void help(char* argv[])
{
  fprintf(stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0]);
  return;
}

void keyreverse()
{
  uint8_t tkey;            // temporary placeholder for key reversal

  _D(fprintf(stdout, "keyreverse(): starting\n");)

  /*****************************************************************************
   *         Important difference between encryption and decryption:
   *                       REVERSE THE KEY SCHEDULE!
   ****************************************************************************/
  for (int i = 0; i < (FEISTEL_ROUNDS - ((FEISTEL_ROUNDS + 1) / 2)); i++)
  {
    tkey = key_lut[i];
    key_lut[i] = key_lut[(FEISTEL_ROUNDS - 1) - i];
    key_lut[(FEISTEL_ROUNDS - 1) - i] = tkey;
  }

  _D(
      for (int i = 0; i < FEISTEL_ROUNDS; i++) fprintf(stdout, "keyreverse(%d): key_lut[%d] = 0x%02x\n", i, i, key_lut[i]);)

}

void keysched(uint8_t round, uint8_t *key_lut)
{

  _D(fprintf(stdout, "keysched(%d): starting ", round);)

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

  _D(fprintf(stdout, "key_lut[%d] = 0x%02x\n", round, key_lut[round]);)

  // call recursively, but not too many times
  if (round + 1 < FEISTEL_ROUNDS)
  {
    keysched(round + 1, key_lut);
  }
  return;
}

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

uint8_t permute(uint8_t hi, uint8_t lo)
{

  _D(fprintf(stdout, "permute(): starting\n");)

  // combine nibbles to get byte
  uint8_t combined = ((hi << 4) | lo);
  uint8_t rolCombined = rol(2, combined);

  _D(
      std::bitset<8> bCombined(combined); std::bitset<8> bRolCombined(rolCombined);

      fprintf(stderr, "permute(): combined: "); cerr << bCombined << " rotated: " << bRolCombined << endl;)

  return rolCombined;
}

uint8_t sbox(uint8_t input)
{

  _D(fprintf(stdout, "sbox(0x%x): ", input);)

  uint8_t lut[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };

  _D(bitset<8> bSbox(lut[input]); cout << bSbox << endl;)

  return lut[input];
}

uint8_t rol(uint8_t shift, const uint8_t input)
{
  return (input << shift) | (input >> (sizeof(input) * 8 - shift));
}

uint8_t _hi8(uint16_t input)
{
  return (input >> 8);
}

uint8_t _lo8(uint16_t input)
{
  return (input & ((1 << 8) - 1));
}

uint8_t _hi4(uint8_t input)
{
  return (input >> 4);
}

uint8_t _lo4(uint8_t input)
{
  return (input & ((1 << 4) - 1));
}

bool _init(int argc, char* argv[], fstream &in, ofstream &out)
{

  _D(fprintf(stdout, "_init(): starting\n");)

  // Show a friendly help message
  if (argc != 5)
  {
    help(argv);
  }

  char *strin;         // relative path to input file
  char *strout;        // relative path to output file
  char *oper;          // operation: E = encrypt / D = decrypt
  unsigned long inlen; // input file length

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

  if ((inlen = in.tellg()) == 0)
  {
    // empty file
    fprintf(stderr, "FATAL: input file %s is empty. Quitting.\n", strin);
    exit(EXIT_FAILURE);
  }

  // assume input files are openable
  if ((*oper == 'E') || (*oper == 'e'))
  {
    mode = 1;

    // check length of input for odd number bytes, pad to even
    if ((inlen % 2) == 1)
    {

      _D(
          fprintf(stdout, "_init(): in length has odd number bytes (%ld). Appending a zero.\n", inlen);)

      in.seekp(inlen);
      in.write("\0", 1);
      in.flush();
    }
  }
  else if ((*oper == 'D') || (*oper == 'd'))
  {
    mode = 0;

    // check length of input for odd number bytes, abort if odd number (bad data)
    if ((inlen % 2) == 1)
    {
      fprintf(stderr,
          "FATAL: cannot decrypt input file %s with odd number of bytes %ld\n",
          strin, inlen);
    }
  }
  else
  {
    help(argv);
    exit(EXIT_FAILURE);
  }

  in.seekp(in.beg); // ensure pointers are definitely at START of file.
  in.seekg(in.beg);

  _D(
      fprintf(stdout, "_init(): in: %s out: %s key: 0x%04x rounds: %d mode: %s \n", strin, strout, starting_key, FEISTEL_ROUNDS, oper);)

  keysched(0, key_lut);

  return mode;
}

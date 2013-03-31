#include <stdio.h>
#include <stdint.h> // uint16_t  - 16 bit unsigned int.
#include <stdlib.h> // strtoul() - string to unsigned long.
#include <string>
#include <fstream>  // ifstream
#include "old_cryptalg.h"

using namespace std;

int main(int argc, char* argv[])
{
  string strinfile;    // relative path to input file
  string stroutfile;   // relative path to output file
  uint16_t key;        // key, eg: 0xCAFE
  char oper;           // operation: E = encrypt / D = decrypt
//  fstream infile;      // input file stream  // TODO: declare me
//  ofstream outfile;    // output file stream // TODO: and initialize separately
  unsigned long inlen; // input file size

  // Show a friendly help message
  if (argc != 5)
  {
    help(argv);
    return 1;
  }

  strinfile = (string) argv[1];
  stroutfile = (string) argv[2];
  key = (uint16_t) strtoul(argv[3], NULL, 0);
  oper = argv[4][0];

  fstream infile(strinfile.c_str(),
      ios::binary | ios::in | ios::out | ios::ate);
  ofstream outfile(stroutfile.c_str(), ios::binary | ios::out | ios::trunc);

  if (!infile)
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strinfile.c_str());
    return 1;
  }
  if (!outfile)
  {
    fprintf(stderr, "FATAL: input file %s could not be opened. Quitting.\n",
        strinfile.c_str());
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
  //////////////////////////////////////////////////////////////////////////////
  // Assuming input is sane, assignment actually starts below.
  //////////////////////////////////////////////////////////////////////////////
  if ((oper == 'E') || (oper == 'e'))
  {
    fprintf(stderr, "encrypt(): in: %s [%09ld bytes] out: %s key: %d\n",
        strinfile.c_str(), inlen, stroutfile.c_str(), key);

    if ((inlen % 2) == 1)
    {
      // append a zero
      fprintf(stderr, "encrypt(): clear text length is odd, appending 0x%02x\n",
          '\0');
      // append 0x00 to input to give an even number of bytes
      infile.seekp(inlen);
      infile.write("\0", 1);
      infile.flush();
      infile.seekp(0);
      inlen++;
      fprintf(stderr, "encrypt(): clear text length = %02ld\n", inlen);
    }

    return encrypt(infile, outfile, key);
  }
  else if ((oper == 'D') || (oper == 'd'))
  {
    fprintf(stderr, "decrypt(): in: %s [%09ld bytes] out: %s key: %d\n",
        strinfile.c_str(), inlen, stroutfile.c_str(), key);

    if ((inlen % 2) == 1)
    {
      // error: odd number of bytes in cipher file
      fprintf(stderr,
          "FATAL: decrypt(): incorrect (odd) number of bytes in input file. aborting.\n");
      return 1;
    }

    return decrypt(infile, outfile, key);
  }

  // Hrm, not encrypt or decrypt, show a friendly help message
  help(argv);
  return 1;
}

/*******************************************************************************
 * Main decrypt function
 ******************************************************************************/
int decrypt(fstream& infile, ofstream& outfile, uint16_t key)
{
  fprintf(stderr, "Running decrypt()\n");
  return 0;
}

/*******************************************************************************
 * Main encrypt function
 ******************************************************************************/
int encrypt(fstream& infile, ofstream& outfile, uint16_t key)
{
  uint8_t buf[BLKSIZE]; // buffer for current bytes to be encrypted
  unsigned long i = 0;  // block size counter

  if (infile)
  {
    infile.seekg(0, infile.beg);  // move get pointer to start of file
  }
  else
  {
    fprintf(stderr,
        "FATAL: encrypt(): Some error happened while trying to read input file. Quitting.\n");
    return 1;
  }

  fprintf(stderr, "encrypt(): starting loop\n");

  while (infile.read((char*) &buf, BLKSIZE))
  {
    fprintf(stderr, "encrypt(): clear block[0x%04x] 0x%02x%02x\n", i, buf[0],
        buf[1]);
    crypt_round(0, buf, key);
    fprintf(stderr, "encrypt(): crypt block[0x%04x] 0x%02x%02x\n", i, buf[0],
        buf[1]);
    outfile.write((char*) &buf, BLKSIZE);
    outfile.flush();
    i++;
  }
  infile.close();
  outfile.close();

  return 0;
}

/**
 * Do a round of encrypt / decrypt
 */
void crypt_round(uint8_t round_num, uint8_t *buf, uint16_t key)
{
  uint8_t Li;
  uint8_t Ri;
  uint8_t Ki;
  uint8_t RiHi;
  uint8_t RiLo;
  uint8_t Pout;
  uint8_t RiNext;
  uint8_t LiNext;

  uint8_t tmp;

  Li = buf[0];
  Ri = buf[1];
  Ki = keysched(round_num,key);

  fprintf(stderr, "crypt_round(): round: %d\n", round_num);
  if (round_num == CBCROUNDS - 1)
  {
    // we have done the correct number of rounds
    return;
  }

  // 1. xor Ri with Ki
  // 2. split result to high and low order nibbles
  // 3. permute RiXoredHigh & RiXoredLow nibbles, reassemble as byte = Pout
  // 4. xor Pout with Li, store as RiNext
  // 5. Ri store as LiNext

  // 1. xor Ri with Ki
  tmp = Ri ^ Ki;

  // 2. split result to high and low order nibbles
  RiHi = (0xff & (tmp >> 4));
  RiLo = (0x00 & (tmp));
  //fprintf(stderr, "crypt_round(): calling crypt_round(%d);\n",round_num+1);
  crypt_round((round_num + 1), buf, key);
}

/**
 * Do a permute
 */
uint8_t permute(uint8_t high, uint8_t low)
{
  rol(high, 2);
  rol(low, 2);
  return (high | low);
}

/**
 * Key Scheduler
 */
uint8_t keysched(uint8_t round, uint16_t key)
{
  // K0 = bits 7..0
  if (round == 0)
  {
    return low8(key);
  }

  // K1 = bits 15..8
  if (round == 1)
  {
    return high8(key);
  }

  // Ki = ROTL^3(Ki-1) xor ROTL^5(Ki-2) | i = 2..7
  return (rol(keysched(round - 1, key), 3) ^ rol(keysched(round - 2, key), 5));
}

uint8_t high8(uint16_t in)
{
  return (uint8_t) (in & 0xff);
}

uint8_t low8(uint16_t in)
{
  return (uint8_t) (in >> 8);
}

/*******************************************************************************
 * S-Box LUT as defined by assignment spec
 ******************************************************************************/
uint8_t sbox(uint8_t input)
{
  uint8_t the_sbox[16] =
  { 0, 1, 11, 13, 9, 14, 6, 7, 12, 5, 8, 3, 15, 2, 4, 10 };
  return the_sbox[input];
}

/**
 * Rotate left (emulate x86 ROL assembly instruction for CPU portability
 * (eg SPARC or ARM instruction sets) )
 *
 * This code comes (almost) completely unaltered from Wikipedia page:
 *  http://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
 *
 * STUDENT DOES NOT CLAIM OWNERSHIP OF THIS FUNCTION.
 */
uint8_t rol(const uint8_t value, uint8_t shift)
{
#ifdef CPU_ROL
  __asm
  {
    rol high, shift
    rol low, shift
  }
#else
  if ((shift &= sizeof(value) * 8 - 1) == 0)
    return value;
  return (value << shift) | (value >> (sizeof(value) * 8 - shift));
#endif
}

/*******************************************************************************
 * Rotate right (emulate x86 ROR assembly instruction for CPU portability
 * (eg SPARC or ARM instruction sets) )
 *
 * This code comes (almost) completely unaltered from Wikipedia page:
 *  http://en.wikipedia.org/wiki/Circular_shift#Implementing_circular_shifts
 *
 * STUDENT DOES NOT CLAIM OWNERSHIP OF THIS FUNCTION.
 ******************************************************************************/
uint8_t ror(const uint8_t value, uint8_t shift)
{
  if ((shift &= sizeof(value) * 8 - 1) == 0)
    return value;
  return (value >> shift) | (value << (sizeof(value) * 8 - shift));
}

/*******************************************************************************
 * Print a friendly help message to STDERR of the form:
 *
 *  cryptalg plain.txt cipher.txt 0xcafe E
 ******************************************************************************/
void help(char* argv[])
{
  fprintf(stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0]);
}

/*
 * double_cryptalg.cc
 *  Created on: 13/04/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */
using namespace std;

#include "globals.h"
#include "helpers.h"
#include "double_cryptalg.h"

int main( int argc, char* argv[] )
{
  _D( fprintf(stdout, "main(): starting\n"); )

  /**
   * in
   * Input file stream. This is actually a bidirectional filestream that is
   * (input and output) because we want to be able to append a trailing 'zero'
   * in the event of an odd number.
   */
  fstream in;   // input file stream
  /**
   * out
   * Output file stream.
   */
  ofstream out; // output file stream

  /**
   * key_lut
   * LUT (Look Up Table) for keys in the scheduling algorithm. While slightly
   * more memory intensive (16bits * number of rounds = 128 bits = 16 bytes in
   * default implementation), it means accessing the key for round i is far less
   * CPU intensive (simply look up rather than generate i rounds for each byte
   * to be encrypted). All key rounds are generated prior to a call to feistel()
   * so they are available for immediate use.
   */
  uint16_t ekey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS]; // encrypt key LUT
  uint16_t dkey_lut[CRYPTO_ROUNDS][FEISTEL_ROUNDS]; // decrypt key LUT

  /**
   * starting_key
   * This is the starting key as provided via the command line.
   */
  uint32_t starting_key;

  /**
   * buf[BLOCK_SIZE]
   * An buffer for bytes read to go into feistel() call.
   */
  uint8_t buf[BLOCK_SIZE];

  _D( unsigned long cur_block; // current buffer iterator
  cur_block = 0; )

  // mode to determine if we are encrypting / decrypting, assigned by _init()
  bool mode;

  double_init( argc, argv, in, out, starting_key, ekey_lut, mode );

  if( !mode )
  {
    // reverse key schedule for decryption
    multi_keyreverse(ekey_lut,dkey_lut);
  }

  /* debug print key schedules */
  _D(
      fprintf(stderr, "EKey schedule:\n");
      for(int i=0; i < CRYPTO_ROUNDS; i++)
        for( int j = 0; j < FEISTEL_ROUNDS; j++ )
          fprintf(stderr,"ekey_lut[%d][%d] = %02x\n",i,j,ekey_lut[i][j]);
      fprintf(stderr, "DKey schedule:\n");
      for(int i=0; i < CRYPTO_ROUNDS; i++)
        for( int j = 0; j < FEISTEL_ROUNDS; j++ )
          fprintf(stderr,"dkey_lut[%d][%d] = %02x\n",i,j,dkey_lut[i][j]);
  ); /* _D() */

  /* read input file block by block to conserve memory for large files
   * (entire program consumes approx 15k of RAM even if using 2byte or 1GB input
   * files)
   */
  while( in.read( (char*) buf, BLOCK_SIZE ) )
  {
    _D(
        fprintf(stderr,
                "********** main(): in  block[0x%04lx] *******************************************\n",
                cur_block);
        fprintf(stderr, "main(): in  block[0x%04lx] 0x%02x%02x", cur_block,
                buf[0], buf[1]);
        bitset<8> l_in(buf[0]);
        bitset<8> r_in(buf[1]);
        cout << " " << l_in << " : " << r_in << endl;
    ); /* _D() */

    if( mode )
      multi_feistel( buf[0], buf[1], ekey_lut );
    else
      multi_feistel( buf[1], buf[0], dkey_lut );

    _D(
        fprintf(stderr, "main(): out block[0x%04lx] 0x%02x%02x", cur_block,
                buf[0], buf[1]);
        bitset<8> l_out(buf[0]);
        bitset<8> r_out(buf[1]);
        cout << " " << l_out << " : " << r_out << endl;
        cur_block++;
    ); /* _D() */

    out.write( (char*) buf, BLOCK_SIZE );
  }

  // close our buffers
  in.close();
  out.close();

  _D( fprintf(stdout, "main(): ending\n"); )
  return 0;
}

/*
 * cryptalg.cc
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
#include "cryptalg.h"

int main( int argc, char* argv[] )
{

  _D( fprintf(stdout, "          main(): starting\n"); )

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
   * LUT (Look Up Table) for keys in the scheduling algorithm. While slightly more
   * memory intensive (16bits * number of rounds = 128 bits = 16 bytes in default
   * implementation), it means accessing the key for round i is far less CPU
   * intensive (simply look up rather than generate i rounds for each byte to be
   * encrypted). All key rounds are generated prior to an encrypt() or decrypt()
   * operation so they are available for immediate use.
   */
  uint16_t ekey_lut[FEISTEL_ROUNDS]; // encryption key lookup table
  uint16_t dkey_lut[FEISTEL_ROUNDS]; // decryption key lookup table

  /**
   * starting_key
   * This is the starting key as provided via the command line.
   */
  uint16_t starting_key;

  /**
   * buf[BLOCK_SIZE]
   * An buffer for bytes read as they get encrypted / decrypted via
   * encrypt() or decrypt() methods.
   */
  uint8_t buf[BLOCK_SIZE];

  _D( unsigned long cur_block; // current buffer iterator
  cur_block = 0; )

  // mode to determine if we are encrypting / decrypting, assigned by _init()
  bool mode;

  init( argc, argv, in, out, starting_key, ekey_lut, mode );

  if(!mode)
  {
    // reverse key schedule for decryption
    keyreverse(ekey_lut,dkey_lut);
  }

  /* read input file block by block to conserve memory for large files
   * (entire program cosumes approx 15k of RAM despite using 2byte or 1GB input
   * files)
   */
  while( in.read( (char*) buf, BLOCK_SIZE ) )
  {
    _D(
        fprintf(stderr, "********* main(): in  block[0x%04lx] ********************************************\n",cur_block);
        fprintf(stderr, "          main():  in block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]);
        bitset<8> l_in(buf[0]);
        bitset<8> r_in(buf[1]);
        cerr << " " << l_in << " : " << r_in << endl;
    );

    if( mode )
    {
      // encrypt
      feistel( 0, buf[0], buf[1], ekey_lut );
    }
    else
    {
      // decrypt
      feistel( 0, buf[1], buf[0], dkey_lut );
    }
    _D(
        fprintf(stderr, "          main(): out block[0x%04lx] 0x%02x%02x", cur_block, buf[0], buf[1]);
        bitset<8> l_out(buf[0]);
        bitset<8> r_out(buf[1]);
        cerr << " " << l_out << " : " << r_out << endl;
    cur_block++; )

    out.write( (char*) buf, BLOCK_SIZE );
  }

  // close our buffers
  in.close();
  out.close();

  _D( fprintf(stderr, "          main(): ending\n"); )
  return 0;
}

bool init( int argc, char* argv[], fstream &in, ofstream &out,
            uint16_t &starting_key, uint16_t (&key_lut)[FEISTEL_ROUNDS],
            bool &mode )
{

  _D( fprintf(stdout, "         _init(): starting\n"); )

// Show a friendly help message
  if( argc != 5 )
  {
    help( argv );
  }

  char *strin;           // relative path to input file
  char *strout;          // relative path to output file
  char *oper;            // operation: E = encrypt / D = decrypt
  unsigned long inlen;   // input file length

  strin = argv[1];
  strout = argv[2];
  starting_key = (uint16_t) strtoul( argv[3], NULL, 0 );
  oper = argv[4];

  in.open( strin, ios::binary | ios::in | ios::out | ios::ate );
  out.open( strout, ios::binary | ios::out | ios::trunc );

// do sanity checks on files now
  if( !in.good() )
  {
    fprintf( stderr, "FATAL: input file %s could not be opened. Quitting.\n",
             strin );
    exit( EXIT_FAILURE );
  }
  if( !out.good() )
  {
    fprintf( stderr, "FATAL: input file %s could not be opened. Quitting.\n",
             strin );
    exit( EXIT_FAILURE );
  }

  if( ( inlen = in.tellg() ) == 0 )
  {
    // empty file
    fprintf( stderr, "FATAL: input file %s is empty. Quitting.\n", strin );
    exit( EXIT_FAILURE );
  }

// assume input files are openable
  if( ( *oper == 'E' ) || ( *oper == 'e' ) )
  {
    mode = 1;

    // check length of input for odd number bytes, pad to even
    if( ( inlen % 2 ) == 1 )
    {

      _D( fprintf(stdout, "         _init(): in length has odd number bytes (%ld). Appending a zero.\n", inlen); )

      in.seekp( inlen );
      in.write( "\0", 1 );
      in.flush();
    }
  }
  else if( ( *oper == 'D' ) || ( *oper == 'd' ) )
  {
    mode = 0;

    // check length of input for odd number bytes, abort if odd number (bad data)
    if( ( inlen % 2 ) == 1 )
    {
      fprintf(
          stderr,
          "FATAL: cannot decrypt input file %s with odd number of bytes %ld\n",
          strin, inlen );
    }
  }
  else
  {
    help( argv );
    exit( EXIT_FAILURE );
  }

  in.seekp( in.beg ); // ensure pointers are definitely at START of file.
  in.seekg( in.beg );

  _D( fprintf(stdout, "         _init():  in: %s \n                  out: %s\n                  key: 0x%04x rounds: %d mode: %s \n", strin, strout, starting_key, FEISTEL_ROUNDS, oper); )

  keysched( 0, starting_key, key_lut );

  return mode;
}

void help( char* argv[] )
{
  fprintf( stderr, "Usage: %s <in.txt> <out.txt> <key> <E|D>\n", argv[0] );
  return;
}

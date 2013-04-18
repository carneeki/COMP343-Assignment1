/*
 * cryptalg.h
 *  Created on: 29/03/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */

#ifndef CRYPTALG_H_
#define CRYPTALG_H_

#ifndef GLOBALS_H_
#include "globals.h"
#endif

#ifndef HELPERS_H_
#include "helpers.h"
#endif

using namespace std;

/**
 * help
 * Help function to display a message showing user how to use the program.
 * Returns 1 and terminates execution.
 * @param argv
 */
void help( char* argv[] );

/**
 * init()
 * Initlize and sanitze variables. Call the help() function if arguments are
 * improperly specified.
 * @param argc argument count
 * @param argv arguments
 * @param in   input file stream
 * @param out  output file stream
 * @param starting_key starting key
 * @param key_lut      key lookup table
 * @param mode         return mode (either encrypt = 1 or decrypt = 0)
 * @return boolean of mode
 */
bool init( int argc, char* argv[], fstream &in, ofstream &out,
            uint16_t &starting_key, uint16_t (&key_lut)[FEISTEL_ROUNDS],
            bool &mode );
/**
 * main()
 * Main program block
 * @param argc Argument count
 * @param argv Argument values
 * @return
 */
int main( int argc, char* argv[] );

#endif /* CRYPTALG_H_ */

/*
 * birthday_attack.h
 *  Created on: 31/03/2013
 *      Author: Adam Carmichael
 *         SID: 41963539
 *
 * Please read the README file for instructions on using make if
 * standard build is not working.
 */

#ifndef BIRTHDAY_ATTACK_H_
#define BIRTHDAY_ATTACK_H_

/**
 * Store chaining variable and message
 */
struct input_pair
{
    uint16_t m; // message
    uint16_t c; // chain variable
}; /* struct input_pair */

#endif

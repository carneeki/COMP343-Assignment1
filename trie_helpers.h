/*
 * trie_helpers.h
 *
 *  Created on: 13/04/2013
 *      Author: carneeki
 */

#ifndef TRIE_HELPERS_H_
#define TRIE_HELPERS_H_

#include <stdexcept>
class NullPointerException: public exception
{
  public:
    virtual const char* what() const throw ()
    {
      return "Null Pointer Exception.";
    }
};

class HashCollisionException: public exception
{
  public:
    virtual const char * what() const throw ()
    {
      return "A hash collision was found.";
    }
};

class RecursionTooDeepException: public exception
{
  public:
    virtual const char* what() const throw ()
    {
      return "Recursion too deep exception.";
    }
};

#endif /* TRIE_HELPERS_H_ */

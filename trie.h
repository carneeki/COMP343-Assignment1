/*
 * trie.h
 *
 * Created on: 11/04/2013
 *     Author: Adam Carmichael <adam.carmichael@students.mq.edu.au
 *        SID: 41963539
 *
 * Author would to acknowledge Mahesh 
 * for inspiration of this Node and Trie class. Original class code can
 * be found at: http://login2win.blogspot.com.au/2011/06/c-tries.html
 *
 * Mahesh contact details: http://www.blogger.com/profile/17421383822093860960
 */

#ifndef TRIE_H_
#define TRIE_H_

#include <iostream>

class Node
{
  private:
    uint16_t m; // message
    uint16_t c; // chaining variable
    Node* l;
    Node* r;
  /* END private: */

  public:
    Node() {}
    ~Node() {}

    void set(uint16_t message, uint16_t chain)
    {
      m = message;
      c = chain;
    } /* void set() */

    uint16_t getMessage()
    {
      return m;
    } /* uint16_t getMessage() */

    uint16_t getChain()
    {
      return c;
    } /* uint16_t getChain() */

    Node* getLeft()
    {
      return l;
    }

    Node* getRight()
    {
      return r;
    }

    void addLeft(Node* left)
    {
      l = left;
    } /*void addLeft */

    void addRight(Node* right)
    {
      r = right;
    } /* void addRight */
  /* END public: */
}

Node* Node::get(uint16_t hash)
{
  // get a node
}

/**
 * Behave like the *nix "touch" command, that is, if a file does not exist,
 * create it. Next, return the node.
 * @return
 */
Node* Node::touch(uint16_t hash)
{
  // Create a node if it does not exist and return

class Trie
{
  private:
    Node* root;
  /* END private: */

  public:
    Trie();
    ~Trie();
    Node* get(uint16_t hash) { }
    Node* touch(uint16_t hash) { }
  /* END public: */
}

Trie::Trie()
{
  root = new Node();
}

Trie::~Trie()
{
  // clean up
}


#endif /* TRIE_H_ */

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

#include "trie_helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <sstream>

class Node
{
  private:
    uint16_t* m; // message
    uint16_t* c; // chaining variable
    Node* l;    // left
    Node* r;    // right
    Node* _get(uint16_t hash, uint8_t ttl);
    /* END private: */

  public:
    Node();
    ~Node();
    void addLeft(Node* left);
    void addRight(Node* right);
    uint16_t* getMessage();
    uint16_t* getChain();
    Node* get(uint16_t hash);
    Node* getLeft();
    Node* getRight();
    void set(uint16_t* message, uint16_t* chain);
    /* END public: */
};

class Trie
{
  private:
    Node* root;
    void _add(uint16_t hash, Node* node, uint8_t ttl, Node* cur);
    /* END private: */

  public:
    Trie();
    ~Trie();
    void add(uint16_t hash, Node* node);
    Node* get(uint16_t hash);
    Node* touch(uint16_t hash);
    /* END public: */
};
/* class Trie */

/** ctor */
Node::Node()
{
  this->m = NULL;
  this->c = NULL;
  this->l = NULL;
  this->r = NULL;
} /* Node::Node() */

/** dtor */
Node::~Node()
{
} /* Node::~Node() */

/**
 * add a node to the left
 * @param left
 */
void Node::addLeft(Node* left)
{
  if(l != NULL)
    throw HashCollisionException();

  l = left;
} /* void Node::addLeft */

/**
 * add a node to the right
 * @param right
 */
void Node::addRight(Node* right)
{
  if(r != NULL)
    throw HashCollisionException();

  r = right;
} /* void Node::addRight */

Node* Node::_get(uint16_t hash, uint8_t ttl)
{
  if (ttl < 0)
    throw RecursionTooDeepException();

  // ensure we are not recursing too deeply
  if (ttl == 0)
    return this;

  // get left / right node based on last binary digit of hash
  if (hash % 2 == 0)
    return this->getLeft();
  else
    return this->getRight();
} /* Node::_get() */

Node* Node::get(uint16_t hash)
{
  return this->_get(hash, 0);
} /* Node::get() */

uint16_t* Node::getMessage()
{
  if(this->m == NULL)
    throw NullPointerException();

  return this->m;
}

uint16_t* Node::getChain()
{

  if(this->c == NULL)
    throw NullPointerException();

  return this->c;
}

Node* Node::getLeft()
{
  if ((this->l) != NULL)
    return this->l;
  else
    throw NullPointerException();
} /* Node::getLeft() */

Node* Node::getRight()
{
  if ((this->r) != NULL)
    return this->r;
  else
    throw NullPointerException();
} /* Node::getRight() */

/**
 * set a node message and chaining variable
 * @param message
 * @param chain
 */
void Node::set(uint16_t* message, uint16_t* chain)
{
  m = message;
  c = chain;
} /* void Node::set() */

Trie::Trie()
{
  root = new Node();
} /* Trie::Trie() */

Trie::~Trie()
{
  // clean up
} /* Trie::~Trie() */

void Trie::_add(uint16_t hash, Node* node, uint8_t ttl, Node* cur)
{
  Node* next = NULL;

  // ensure we are not recursing too deeply
  if (ttl < 0)
    throw RecursionTooDeepException();

  // if we are at the end of the hash, store the message in the trie
  if (ttl == 0)
  {
    if ((hash % 2 == 0))
    {
      cur->addLeft(node);  // even value - node belongs left
      return;
    }
    else
    {
      cur->addRight(node); // odd value - node belongs right
      return;
    }
    return;
  }

  // go to the next layer down the trie
  if ((hash % 2 == 0))
  {
    // left node
    try { next = cur->getLeft(); }
    catch (const NullPointerException& e)
    {
      next = new Node();
      cur->addLeft(next);
    }
  }
  else
  {
    // left node
    try { next = cur->getRight(); }
    catch (const NullPointerException& e)
    {
      next = new Node();
      cur->addRight(next);
    }
  }

  ttl--;

  _add((hash >> 1), node, ttl, next);
  return;
} /* Trie::_add() */

void Trie::add(uint16_t hash, Node* node)
{
  _add(hash, node, 16, this->root);
} /* Trie::add() */

#endif /* TRIE_H_ */

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

#define TRIE_NULL_PTR 0
#define TRIE_HASH_COLLISION 1

class Node
{
  private:
    uint16_t* m; // message
    uint16_t* c; // chaining variable
    Node* l;    // left
    Node* r;    // right
    Node* _get(uint16_t hash, uint8_t level);
    /* END private: */

  public:
    Node();
    ~Node();
    void addLeft(Node* left);
    void addRight(Node* right);
    uint16_t getMessage();
    uint16_t getChain();
    Node* get(uint16_t hash);
    Node* getLeft();
    Node* getRight();
    void set(uint16_t message, uint16_t chain);
    /* END public: */
};

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
  this->l = left;
} /* void Node::addLeft */

/**
 * add a node to the right
 * @param right
 */
void Node::addRight(Node* right)
{
  this->r = right;
} /* void Node::addRight */

Node* Node::_get(uint16_t hash, uint8_t level)
{
  Node* retval; // return value

  // ensure we are not recursing too deeply
  if (level == (sizeof(uint16_t) * 8))
  {
    return (Node*) this;
  }

  // get left / right node based on last binary digit of hash
  if (hash % 2 == 0)
  {
    retval = this->l;
  }
  else
  {
    retval = this->r;
  }
  if (retval != NULL) // handle null cases rather than breaking
  {
    return retval->_get((hash >> 1), level++);
  }
  else
  {
    throw TRIE_NULL_PTR;
  }
} /* Node::_get() */

Node* Node::get(uint16_t hash)
{
  return this->_get(hash, 0);
} /* Node::get() */

/**
 * set a node message and chaining variable
 * @param message
 * @param chain
 */
void Node::set(uint16_t message, uint16_t chain)
{
  m = &message;
  c = &chain;
} /* void Node::set() */

class Trie
{
  private:
    Node* root;
    void _add(uint16_t hash, Node* node, uint8_t level, Node* cur);
    /* END private: */

  public:
    Trie();
    ~Trie();
    void add(uint16_t hash, Node* node);
    Node* get(uint16_t hash);
    Node* touch(uint16_t hash);
    /* END public: */
}; /* class Trie */

Trie::Trie()
{
  root = new Node();
} /* Trie::Trie() */

Trie::~Trie()
{
  // clean up
} /* Trie::~Trie() */

void Trie::_add(uint16_t hash, Node* node, uint8_t level, Node* cur)
{
  Node* next;
  // ensure we are not recursing too deeply
  if (level == (sizeof(uint16_t) * 8))
  {
    throw -1; // TODO: add a proper exception here
  }

  if ((hash % 2 == 0))
  {
    // left node
    next = cur->getLeft();
  }
  else
  {
    // right node
    next = cur->getRight();
  }

  if (next == NULL)
  {
    next = new Node();
  }

  _add((hash >> 1), node, level++, next);
} /* Trie::_add() */

void Trie::add(uint16_t hash, Node* node)
{
  if (root->get(hash))
  {
    throw TRIE_HASH_COLLISION;
  }

  _add(hash, node, 0, this->root);
} /* Trie::add() */

#endif /* TRIE_H_ */

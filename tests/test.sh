#!/bin/bash

TIMEFORMAT='%3R'

MODE="Debug"
PROGNAME="cryptalg"
KEY="0xCAFE"

make-n()
{
  PREFIX=$1m
  POSTFIX=dd
  dd if=/dev/urandom of=$PREFIX.clear.$POSTFIX bs=1M count=$1
}

test-n()
{
  PREFIX=$1m
  POSTFIX=dd
  do-test
}

make-big()
{
  big
  dd if=/dev/urandom of=$PREFIX.clear.$POSTFIX bs=4M count=256
}

make-small()
{
  small
  echo -n "ADAM" > $PREFIX.clear.$POSTFIX
}

big()
{
  PREFIX=big
  POSTFIX=dd
}

clean()
{
  rm -rf *clear2*
  rm -rf *crypt*
}

purge()
{
  rm -rf *clear*
  rm -rf *crypt*
}

payload()
{
  PREFIX="payload"
  POSTFIX="jpg"
}

small()
{
  PREFIX="small"
  POSTFIX="txt"
}

do-test()
{
  time nice -19 ../$MODE/$PROGNAME $PREFIX.clear.$POSTFIX $PREFIX.crypt.$POSTFIX $KEY E
  time nice -19 ../$MODE/$PROGNAME $PREFIX.crypt.$POSTFIX $PREFIX.clear2.$POSTFIX $KEY D
}

md5()
{
  md5sum $PREFIX.*
}

case $1 in
  "make-big" )
    make-big
  ;;
  "make-small" )
    make-small
  ;;
  "test-n")
    test $2
    do-test
  ;;
  "big" )
    big
    do-test
    md5
  ;;
  "clean" )
    clean
  ;;
  "payload" )
    payload
    do-test
    md5
  ;;
  "purge" )
    purge
  ;;
  "small" )
    small
    do-test
    md5
  ;;
  "suite" )
    for BITS in {0..10}
      do
        SIZE=$((2**$BITS))
        echo "Size: 2^$BITS=$SIZE TEST *****"
#        make-n $SIZE
        test-n $SIZE
        echo "Size: 2^$BITS=$SIZE DONE *****"
      done
esac

#!/bin/bash

TIMEFORMAT='%3R'

MODE="Release"
PROGNAME="cryptalg"
KEY="0xCAFE"

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
  time ../$MODE/$PROGNAME $PREFIX.clear.$POSTFIX $PREFIX.crypt.$POSTFIX $KEY E
  time ../$MODE/$PROGNAME $PREFIX.crypt.$POSTFIX $PREFIX.clear2.$POSTFIX $KEY D
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
esac

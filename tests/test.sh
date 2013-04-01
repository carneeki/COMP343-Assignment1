#!/bin/bash

TIMEFORMAT='%3R'

MODE="Release"
PROGNAME="cryptalg"
KEY="0xCAFE"

make-big()
{
  dd if=/dev/urandom of=big.clear.dd bs=4M count=256
}

big()
{
  PREFIX=big
  POSTFIX=dd
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
  "big" )
    big
    do-test
    md5
  ;;
  "payload" )
    payload
    do-test
    md5
  ;;
  "small" )
    small
    do-test
    md5
  ;;
esac

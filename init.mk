# Put variables applicable to all builds and all targets here

CP := cp
DD := dd
CKSUM := sha512sum
NICE := nice
RM := rm -rf
TIME := /usr/bin/time


CKSUM_DB = CHECKSUMS.SHA512
CKSUM_FLAGS = -b
CKSUM_CKFLAGS = --check
NICE_LVL = -19
SHELL = /bin/bash
TIMEFORMAT= -f "wall: %E, user: %U, kern: %S"  

CPP = g++
CFLAGS += -c -Wall -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)"
LDFLAGS += -Wall -fmessage-length=0
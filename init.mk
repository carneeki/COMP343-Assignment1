# Put variables applicable to all builds and all targets here

RM := rm -rf
CP := cp
DD := dd
CKSUM := sha512sum
CKSUM_DB = CHECKSUMS.SHA512
CKSUM_FLAGS = -b
CKSUM_CKFLAGS = --check

CPP = g++
CFLAGS += -c -Wall -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)"
LDFLAGS += -Wall -fmessage-length=0
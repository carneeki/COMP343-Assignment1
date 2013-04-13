# Put variables applicable to all builds and all targets here

RM := rm -rf

CPP = g++
CFLAGS += -c -Wall -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)"
LDFLAGS += -Wall -fmessage-length=0
#-include ../makefile.init

RM := rm -rf
CP := cp
DD := dd
CKSUM := sha512sum
CKSUM_DB = CHECKSUMS.SHA512
CKSUM_FLAGS = -b
CKSUM_CKFLAGS = --check

TEST_CLEARI_FILE = m.clearI.dd
TEST_CLEARO_FILE = m.clearO.dd
TEST_CRYPT_FILE = m.crypt.dd
TEST_KEY = 0xCAFE
# All of the sources participating in the build are defined here
#-include sources.mk
#-include subdir.mk
#-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: birthday_attack cryptalg

birthday_attack: birthday_attack.o
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CPP) $(LDFLAGS) $@.o -o $@
	@echo 'Finished building target: $@'
	@echo ' '

birthday_attack.o:
	@echo 'Building file: ../birthday_attack.cc'
	@echo 'Invoking: GCC C++ Compiler'
	$(CPP) $(CFLAGS) -c ../birthday_attack.cc -o $@
	@echo 'Finished building: $@'
	@echo ' '

birthday_attack_test: birthday_attack
	@echo 'Running binary: ./birthday_attack'
	./birthday_attack
	echo 'Done! '
	
cryptalg: cryptalg.o
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CPP) $(LDFLAGS) $@.o -o $@
	@echo 'Finished building target: $@'
	@echo ' '

cryptalg.o:
	@echo 'Building file: ../cryptalg.cc'
	@echo 'Invoking: GCC C++ Compiler'
	$(CPP) $(CFLAGS) -c ../cryptalg.cc -o $@
	@echo 'Finished building: $@'
	@echo ' '

cryptalg_test: cryptalg test_files
	@echo 'Running binary: ./cryptalg '
	@$(foreach MB, 1 2 4 8 16 32,\
		echo 'Running test on: $(MB)m';\
		./cryptalg $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CRYPT_FILE) $(value TEST_KEY) E;\
		./cryptalg $(MB)$(value TEST_CRYPT_FILE) $(MB)$(value TEST_CLEARO_FILE) $(value TEST_KEY) D;\
	)
	@$(CKSUM) $(CKSUM_CKFLAGS) $(CKSUM_DB);\
	echo ' '

double_cryptalg: double_cryptalg.o
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CPP) $(LDFLAGS) $@.o -o $@
	@echo 'Finished building target: $@'
	@echo ' '

double_cryptalg.o:
	@echo 'Building file: ../double_cryptalg.cc'
	@echo 'Invoking: GCC C++ Compiler'
	$(CPP) $(CFLAGS) -c ../double_cryptalg.cc -o $@
	@echo 'Finished building: $@'
	@echo ' '

double_cryptalg_test: double_cryptalg test_files
	@echo 'Running binary: ./double_cryptalg '
	@$(foreach MB, 1 2 4 8 16 32,\
		echo 'Running test on: $(MB)m';\
		./double_cryptalg $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CRYPT_FILE) $(value TEST_KEY) E;\
		./double_cryptalg $(MB)$(value TEST_CRYPT_FILE) $(MB)$(value TEST_CLEARO_FILE) $(value TEST_KEY) D;\
	)
	@$(CKSUM) $(CKSUM_CKFLAGS) $(CKSUM_DB);\
	echo 'Done! '

double_cipher_attack:	double_cipher_attack.o
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CPP) $(LDFLAGS) $@.o -o $@
	@echo 'Finished building target: $@'
	@echo ' '

double_cipher_attack.o:
	@echo 'Building file: ../double_cipher_attack.cc'
	@echo 'Invoking: GCC C++ Compiler'
	$(CPP) $(CFLAGS) -c ../double_cipher_attack.cc -o $@
	@echo 'Finished building: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) \
		*.d \
		*.o \
		birthday_attack \
		cryptalg \
		double_cipher_attack \
		double_cryptalg \
		*$(value TEST_CLEARI_FILE)* \
		*$(value TEST_CLEARO_FILE)* \
		*$(value TEST_CRYPT_FILE)* \
		$(CKSUM_DB)
	-@echo ' '

test_files:
	@echo 'Removing old checksum database: $(CKSUM_DB)'
	@$(RM) $(CKSUM_DB)
	@$(foreach MB, 1 2 4 8 16 32,\
		echo 'Creating test file: $(MB)$(value TEST_CLEARI_FILE)' ;\
		$(DD) if=/dev/urandom of=$(MB)$(value TEST_CLEARI_FILE) bs=$(MB)M count=1 2> /dev/null ;\
		$(CP) $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CLEARO_FILE) ;\
		$(CKSUM) $(CKSUM_FLAGS) $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CLEARO_FILE) >> $(CKSUM_DB) ;\
		$(RM) $(MB)$(value TEST_CLEARO_FILE) ;\
	)
	@echo ' '

.PHONY: all clean dependents
.SECONDARY:

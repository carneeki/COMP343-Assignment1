#-include ../makefile.init

TEST_CLEARI_FILE = m.clearI.dd
TEST_CLEARO_FILE = m.clearO.dd
TEST_CRYPT_FILE = m.crypt.dd
TEST_KEY = 0xCAFE
TEST_DOUBLE_KEY = 0xFEEDCAFE
TEST_BIG_FILESIZE = 1024
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
all: birthday_attack cryptalg double_cipher_attack double_cryptalg

sample_birthday: sample_birthday.o
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	$(CPP) $(LDFLAGS) $@.o -o $@
	@echo 'Finished building target: $@'
	@echo ' '

sample_birthday.o:
	@echo 'Building file: ../sample_birthday.cc'
	@echo 'Invoking: GCC C++ Compiler'
	$(CPP) $(CFLAGS) -c ../sample_birthday.cc -o $@
	@echo 'Finished building: $@'
	@echo ' '

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
	echo ' '
	
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
		echo -n 'Running encrypt on: $(MB)m';\
		$(TIME) $(TIMEFORMAT) $(NICE) $(NICE_LVL) ./cryptalg $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CRYPT_FILE) $(value TEST_KEY) E;\
		echo ' ';\
		echo -n 'Running decrypt on: $(MB)m';\
		$(TIME) $(TIMEFORMAT) $(NICE) $(NICE_LVL) ./cryptalg $(MB)$(value TEST_CRYPT_FILE) $(MB)$(value TEST_CLEARO_FILE) $(value TEST_KEY) D;\
		echo ' ';\
	)
	@$(CKSUM) $(CKSUM_CKFLAGS) $(CKSUM_DB);\
	echo ' '

cryptalg_test_big: cryptalg test_file_big
	@echo 'Running binary: ./cryptalg '
	echo -n 'Running encrypt on: $(value TEST_BIG_FILESIZE)m';\
	$(TIME) $(TIMEFORMAT) $(NICE) $(NICE_LVL) ./cryptalg $(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) $(value TEST_BIG_FILESIZE)$(value TEST_CRYPT_FILE) $(value TEST_KEY) E
	echo -n 'Running decrypt on: $(value TEST_BIG_FILESIZE)m';\
	$(TIME) $(TIMEFORMAT) $(NICE) $(NICE_LVL) ./cryptalg $(value TEST_BIG_FILESIZE)$(value TEST_CRYPT_FILE) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARO_FILE) $(value TEST_KEY) D
	@$(CKSUM) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARO_FILE)
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
		./double_cryptalg $(MB)$(value TEST_CLEARI_FILE) $(MB)$(value TEST_CRYPT_FILE) $(value TEST_DOUBLE_KEY) E;\
		./double_cryptalg $(MB)$(value TEST_CRYPT_FILE) $(MB)$(value TEST_CLEARO_FILE) $(value TEST_DOUBLE_KEY) D;\
	)
	@$(CKSUM) $(CKSUM_CKFLAGS) $(CKSUM_DB);\
	echo ' '

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

double_cipher_attack_test: double_cipher_attack
	@echo 'Running binary: ./double_cipher_attack'
	@ ./double_cipher_attack
	echo ' '

# Other Targets
clean:
	-$(RM) \
		*.d \
		*.o \
		birthday_attack \
		cryptalg \
		double_cipher_attack \
		double_cryptalg \
		*$(value TEST_CLEARI_FILE) \
		*$(value TEST_CLEARO_FILE) \
		*$(value TEST_CRYPT_FILE) \
		*$(CKSUM_DB) \
		SSH_*
	-@echo ' '

test_all: clean cryptalg_test cryptalg_test_big birthday_attack_test double_cryptalg_test double_cipher_attack_test

test_file_big:
	@if [ -f $(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) ]; then \
		echo "Big file exists. Skipping create..."; \
	else \
		echo "Creating big file"; \
		$(DD) if=/dev/urandom of=$(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) bs=$(value TEST_BIG_FILESIZE)M count=1 2> /dev/null ; \
	fi
	@$(CP) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARO_FILE)
	@$(CKSUM) $(CKSUM_FLAGS) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARI_FILE) $(value TEST_BIG_FILESIZE)$(value TEST_CLEARO_FILE) >> $(CKSUM_DB)
	@echo ' '

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

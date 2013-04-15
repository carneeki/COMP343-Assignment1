#-include ../makefile.init

RM := rm -rf

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
test_birthday_attack: birthday_attack
	@echo 'Running binary: ./birthday_attack'
	./birthday_attack
	echo 'Done! '

# Other Targets
clean:
	-$(RM) \
		*.d \
		*.o \
		birthday_attack \
		cryptalg \
		double_cipher_attack
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

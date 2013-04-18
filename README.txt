##############################################################################
#
# COMP343 2013 Semester 1 Assignment 1
#
# Author: Adam Carmichael <carneeki@carneeki.net>
#    SID: 4196 3539
#
##############################################################################

Table of Contents:
  Project Layout
  Makefile Instructions
  Build Environment & Requirements
  
##############################################################################  
# Project Layout
##############################################################################
The project exists with all source files existing in the project root, as well
as makefile includes that are required for building binaries and test cases.
.
├── .git                    - git-scm repository
│   └── ...                 - more of the revision control repository... best
│                             ignore this and use git commands to access repo
├── .gitignore              - git ignore files
├── Debug                   - Debug build
│   ├── makefile            - GNU Makefile for debug builds
│   └── subdir.mk           - Debug build specific directives
├── Release                 - Release build (this is the one you want to look at
│   │                         for marking!
│   ├── makefile            - GNU Makefile for release builds
│   └── subdir.mk           - Release build specific directives
├── birthday_attack.cc      - Birthday attack implementation for part (2)
├── cryptalg.cc             - Cryptographic algorithm for part (1)
├── cryptalg.h              - Header file for cryptographic algorithm part(1)
├── double_cipher_attack.cc - Meet-in-the-middle attack for part (3b)
├── double_cipher_attack.h  - Header file for part (3b)
├── double_cryptalg.cc      - Double encryption for part (3a)
├── double_cryptalg.h       - Header file for part (3a)
├── helpers.h               - Helper functions which were common for most of the
│                             project
├── init.mk                 - Makefile initializer
├── README.txt              - This file.
├── targets.mk              - Targets (outlined in Makefile Instructions)
├── .cproject               - Eclipse project details
└── .projects               - more Eclipse specific stuff... just ignore

##############################################################################  
# Makefile Instructions
##############################################################################
make all        - will make all targets except for test cases
make test_files - will make test case files using the dd command to generate
                  random binary data.
make test_all   - make all binaries and run all tests

make cryptalg      - part (1) of the assignment
make cryptalg_test - test part (1) by calling the cryptalg binary with a
                     checksum command to check that the file, once encrypted and
                     subsequently decrypted matches the original clear file
                     (sha512sum used by default, can be changed by modifying the
                     CKSUM variable in the make file)
make birthday_attack      - part (2) of the assignment
make birthday_attack_test - test part(2) by running the ./birthday_attack binary
make double_cryptalg      - part (3a) of the assignment
make double_cryptalg_test - test part (3a) of the assignment much the same way
                            cryptalg_test operates.
make double_cipher_attack      - part (3b) of the assignment
make double_cipher_attack_test - test part (3b) of the assignment much the same
                                 way the birthday attack test works.

##############################################################################
# Build environment & Requirements
##############################################################################
Project was built on a Linux workstation.

It requires GNU Make as well as GNU compiler collection to build all projects.
No additional libraries outside of GNU's standard libc and libstdc++
distribution were used.

Additionally, to run test cases, a checksum utility (such as sha512sum or
md5sum) is required. This can be modified by editing ./init.mk and setting the
CKSUM variable. When modifying, please also adjust the appropriate flags and
ckflags variables. CKSUM_FLAGS are appended to CKSUM for flags when building an
index of checksum files (into CKSUM_DB). CKSUM_CKFLAGS are appended when
comparing against the CKSUM_DB.

To generate test case files, the dd command is required, as well as a source of
entropy. If this must be changed, it is best to edit the appropriate in the
test_files target.

git-scm and a private GitHub repository were used to track and manage source
code revisions. From April 30th, the source repository will be made public and
history between revisions and branches can be found. The repository address will
likely be https://github.com/carneekiNET/COMP343-Assignment1
A copy of the .git repository has been attached for immediate use.

##############################
### Linux version
$ uname -a
Linux miss-of-arc 3.5.0-17-generic #28-Ubuntu SMP Tue Oct 9 19:31:23 UTC 2012
x86_64 x86_64 x86_64 GNU/Linux

##############################
### g++ version
$ g++ --version
g++ (Ubuntu/Linaro 4.7.2-2ubuntu1) 4.7.2
Copyright (C) 2012 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

##############################
### make version
$ make --version
GNU Make 3.81
Copyright (C) 2006  Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.

This program built for x86_64-pc-linux-gnu

##############################
### dd version
dd --version
dd (coreutils) 8.13
Copyright (C) 2011 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Paul Rubin, David MacKenzie and Stuart Kemp.

##############################
### sha512sum version
$ sha512sum --version
sha512sum (GNU coreutils) 8.13
Copyright (C) 2011 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Ulrich Drepper, Scott Miller and David Madore.
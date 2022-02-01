//
// Created by student on 1/26/22.
//

#include <stdio.h>
#include <string.h>
#include "elf64.h"
#include <stdlib.h>
#include <stdbool.h>

#ifndef ATAM_HW_4_ATTEMPT_1_ELF_DECODER_H
#define ATAM_HW_4_ATTEMPT_1 _ELF_DECODER_H

#define SYMBOL_NOT_EXISTS -1
#define SYMBOL_NAME_NOT_GLOBAL -2
#define ELF_NOT_EXEC -3

long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count);

#endif //ATAM_HW_4_ATTEMPT_1_ELF_DECODER_H

#include <stdio.h>
#include <string.h>
#include "elf64.h"
#include <stdlib.h>
#include <stdbool.h>
#include "elf_decoder.h"

bool cmp_symbol_name(FILE* elf_file, Elf64_Off offset, Elf64_Word st_name, char* symbol_name){

    fseek(elf_file, offset + st_name, SEEK_SET);

    char  temp;

    for (int i = 0; i < strlen(symbol_name); ++i) {
        fread(&temp, sizeof(char), 1, elf_file);
        if(temp == '\0' || temp != symbol_name[i]){
            return false;
        }
    }

    fread(&temp, sizeof(char), 1, elf_file);

    if(temp == '\0'){
        return true;
    }else{
        return false;
    }

}

long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count){
	
	Elf64_Ehdr elf_file_header;
	
	FILE* elf_file = fopen(exe_file_name, "r");
	
	fread(&elf_file_header, sizeof(Elf64_Ehdr), 1, elf_file);
	
	if(elf_file_header.e_type != 0x02){
		return ELF_NOT_EXEC;
	}

	fseek(elf_file, elf_file_header.e_shoff, SEEK_SET);

	Elf64_Shdr* section_headers_table = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*(elf_file_header.e_shnum));
	fread(section_headers_table, sizeof(Elf64_Shdr), elf_file_header.e_shnum, elf_file);
	
	int symb_table_index;

	for(Elf64_Half i = 0; i < elf_file_header.e_shnum; i++){
		if(section_headers_table[i].sh_type == 2){
			symb_table_index = i;
			break;
		}
	}

	fseek(elf_file, section_headers_table[symb_table_index].sh_offset, SEEK_SET);
	
	Elf64_Xword num_symbols = section_headers_table[symb_table_index].sh_size/section_headers_table[symb_table_index].sh_entsize;
	Elf64_Sym* sym_table = (Elf64_Sym*)malloc(sizeof(Elf64_Sym)*num_symbols);
	fread(sym_table, sizeof(Elf64_Sym), num_symbols, elf_file);
	
	unsigned int local_count_int = 0;
	bool symbol_global_exists = false;
	Elf64_Addr global_symbol_val;
	
	for(Elf64_Xword i = 0; i < num_symbols; i++){
		if(cmp_symbol_name(elf_file, section_headers_table[section_headers_table[symb_table_index].sh_link].sh_offset, sym_table[i].st_name, symbol_name)){
			if(ELF64_ST_BIND(sym_table[i].st_info) == 1){
				symbol_global_exists = true;
				global_symbol_val = sym_table[i].st_value;
			} else if(ELF64_ST_BIND(sym_table[i].st_info) == 0){
				local_count_int++;
			}
		}
	}

	free(sym_table);
	free(section_headers_table);
	fclose(elf_file);
	
	(*local_count) = local_count_int;
	if(symbol_global_exists){
		return global_symbol_val;
	}else if(local_count_int > 0){
		return SYMBOL_NAME_NOT_GLOBAL;
	}else{
		return SYMBOL_NOT_EXISTS;
	}
}

















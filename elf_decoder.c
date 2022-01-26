#include <stdio.h>
#include <string.h>
#include "elf64.h"

#define SYMBOL_NOT_EXISTS -1
#define SYMBOL_NAME_NOT_GLOBAL -2
#define ELF_NOT_EXEC -3

unsigned long find_symbol(char* symbol_name, char* exe_file_name, unsigned int* local_count){
	
	Elf64_Sym elf_file_header;
	
	FILE* elf_file = fopen(exe_file_name, "rb");
	
	fread(&elf_file_header, sizeof(elf_file_header), 1, elf_file);
	
	if(elf_file_header -> e_type != 0x02){
		return ELF_NOT_EXEC;
	}

	fseek(elf_file, elf_file_header.e_dhoff, SEEK_SET);

	Elf64_Shdr* section_headers_table = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr)*(elf_file_header.e_shnum));
	fread(section_headers_table, sizeof(Elf64_Shdr), elf_file_header.e_shnum, elf);
	
	int symb_table_index;

	for(Elf64_Half i = 0, i < elf_file_header.e_shnum, i++){
		if(section_headers_table[i].sh_type == SHT_SYMTAB){
			symb_table_index = i;
			break;
		}
	}

	fseek(elf, section_headers_table[symb_table_index].sh_offset, SEEK_SET);
	
	Elf64_Xword num_symbols = section_headers_table[symb_table_index].sh_size/section_headers_table[symb_table_index].sh_entsize;
	Elf64_Sym* sym_table = (Elf64_Sym*)malloc(sizeof(Elf64_Sym)*num_symbols);
	fread(sym_table, sizeof(Elf64_Sym), num_symbols, elf);
	
	unsigned int local_count_int = 0;
	bool symbol_global_exists = false;
	Elf64_Addr global_symbol_val;
	
	for(Elf_Xword i = 0; i < num_symbols; i++;){
		if(!strcmp(sym_table[i].st_name, symbol_name)){
			if(ELF64_ST_BIND(sym_table[i].st_info) == GLOBAL){
				symbol_global_exists = true;
				global_symbol_val = sym_table[i].st_value;
			}
			if(ELF64_ST_BIND(sym_table[i].st_info) == LOCAL){
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

















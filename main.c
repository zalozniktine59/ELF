//Implementira delovanje programa elf_changer, ki omogoča razčlenitev in izpis formata ELF, ter njegovo spreminjanje. 
//Program naj podpira uporabo naslednjih zastavic, kot obvezni argument pa prejme pot do zbirke v formatu ELF, ki jo želimo analizirati:

/*
elf_loader [-hlc] [OPTIONS] elf_path

-h
  izpis zaglavja zbirke podane v elf_path

-l
  izpis vseh funkcij, ki jih najdete v .text sekciji in imajo velikost večjo od 20 zlogov

-c [spr1,spr2,spr3,...]
  spreminjanje vrednosti vseh spremeljivk programa za +20, ki jih lahko najdete v programu v elf_path

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// Definiramo strukturo ELFHeader, ki ustreza glavi ELF datoteke
/*
typedef struct {
    unsigned char ident[16];
    //unsigned char ident[EI_NIDENT];
    unsigned short type;
    unsigned short machine;
    unsigned int version;
    unsigned long entry;
    unsigned long phoff; //offset za program header table
    unsigned long shoff; //offset za section header table - torej tuki so drug za drugim 64B vlki section headerji
    unsigned int flags;
    unsigned short ehsize;
    unsigned short phentsize;
    unsigned short phnum;
    unsigned short shentsize; // size per section header
    unsigned short shnum; // number of section headers
    unsigned short shstrndx; // section header string table index (torej samo kater section po vrsti je) - tole pointa na section number that contains a string table containing the name of the sections
} ELFHeader;
*/

// Definiramo strukturo ELFSection, ki predstavlja vnos v tabeli sekcij
struct Elf64_Shdr {
    uint32_t sh_name;       // Section name - torej to je offset v section header string table
    uint32_t sh_type;       // Section type
    uint64_t sh_flags;      // Section flags
    uint64_t sh_addr;       // Address where section is loaded into memory
    uint64_t sh_offset;     // File offset of the section
    uint64_t sh_size;       // Size of the section
    uint32_t sh_link;       // Link to other sections
    uint32_t sh_info;       // Additional section information
    uint64_t sh_addralign;  // Alignment of the section
    uint64_t sh_entsize;    // Size of each entry, if section has fixed-size entries
};


const char *getElfClass(unsigned char elfClass) {
    switch (elfClass) {
        case 1:
            return "ELF32";
        case 2:
            return "ELF64";
        default:
            return "Unknown";
    }
}

const char *getDataEncoding(unsigned char dataEncoding) {
    switch (dataEncoding) {
        case 1:
            return "2's complement, little endian";
        case 2:
            return "2's complement, big endian";
        default:
            return "Unknown";
    }
}

const char *getOSABI(unsigned char osabi) {
    switch (osabi) {
        case 0:
            return "UNIX - System V";
        case 1:
            return "HP-UX";
        case 2:
            return "NetBSD";
        case 3:
            return "Linux";
        default:
            return "Unknown";
    }
}
const char *getElfType(unsigned short type) {
    switch (type) {
        case 1:
            return "REL (Relocatable file)";
        case 2:
            return "EXEC (Executable file)";
        case 3:
            return "DYN (Shared object file)";
        case 4:
            return "CORE (Core file)";
        default:
            return "Unknown";
    }
}

const char *getMachineType(unsigned short machine) {
    switch (machine) {
        case 0x03:
            return "Intel 80386";
        case 0x3E:
            return "AMD x86-64";
        default:
            return "Unknown";
    }
}


size_t getSectionHeaderIndex(Elf64_Ehdr *header, char *file, const char *section_name) {
    // Calculate the offset of the section header string table section header
    size_t shstrtab_header_offset = header->e_shoff + (header->e_shentsize * header->e_shstrndx);
    // Access the section header directly from mapped memory
    Elf64_Shdr *shstrtab_header = (Elf64_Shdr *)((char *)file + shstrtab_header_offset);
    // 2. Read the string table
    char *shstrtab = (char *)file + shstrtab_header->sh_offset;
    size_t strtab_size = shstrtab_header->sh_size;
    // Iterate over the section headers
    for (int i = 0; i < header->e_shnum; i++) {
        // Calculate the offset of the current section header
        size_t section_offset = header->e_shoff + (header->e_shentsize * i);
        
        // Access the section header directly from mapped memory
        Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)file + section_offset);
        
        // Check if the section is in the .text section
        if (strcmp(shstrtab + section_header->sh_name, section_name) == 0) {
            //#printf("Section name: %s\n", shstrtab + section_header->sh_name);
            //printf("Function size: %lu\n", section_header->sh_size);
            //printf("Section offset: %lu\n", section_header->sh_offset);
            //printf("Section header index: %d\n", i);
            return i;
        }
    }
}

Elf64_Shdr* getSectionHeader(Elf64_Ehdr *header, char *file, const char *section_name) {

    // Calculate the offset of the section header string table section header
    size_t shstrtab_header_offset = header->e_shoff + (header->e_shentsize * header->e_shstrndx);
    // Access the section header directly from mapped memory
    Elf64_Shdr *shstrtab_header = (Elf64_Shdr *)((char *)file + shstrtab_header_offset);
    // 2. Read the string table
    char *shstrtab = (char *)file + shstrtab_header->sh_offset;
    size_t strtab_size = shstrtab_header->sh_size;
    // Iterate over the section headers
    for (int i = 0; i < header->e_shnum; i++) {
        // Calculate the offset of the current section header
        size_t section_offset = header->e_shoff + (header->e_shentsize * i);
        
        // Access the section header directly from mapped memory
        Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)file + section_offset);
        
        // Check if the section is in the .text section
        if (strcmp(shstrtab + section_header->sh_name, section_name) == 0) {
            //#printf("Section name: %s\n", shstrtab + section_header->sh_name);
            //printf("Function size: %lu\n", section_header->sh_size);
            //printf("Section offset: %lu\n", section_header->sh_offset);
            return section_header;
        }
    }
}
void print_symtab_functions(Elf64_Shdr *symtab_header, Elf64_Ehdr *header, char *file) {
    // Get the string table section associated with the symbol table
    Elf64_Shdr *strtab_header = (Elf64_Shdr *)((char *)header + header->e_shoff + (symtab_header->sh_link * header->e_shentsize));
    char *strtab = file + strtab_header->sh_offset;


    // Iterate over the symbol table entries
    Elf64_Sym *symtab = (Elf64_Sym *)(file + symtab_header->sh_offset);
    for (int i = 0; i < symtab_header->sh_size / sizeof(Elf64_Sym); i++) {
        // Check if the symbol is a function
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC && symtab[i].st_size > 20) {
            // Get the function name from the string table
            char *func_name = strtab + symtab[i].st_name;
            printf("%s\n", func_name);
        }
    }
}
void print_symtab_variables(Elf64_Shdr *symtab_header, Elf64_Ehdr *header, char *file, int fd) {
    // Get the string table section associated with the symbol table
    Elf64_Shdr *strtab_header = (Elf64_Shdr *)((char *)header + header->e_shoff + (symtab_header->sh_link * header->e_shentsize));
    char *strtab = file + strtab_header->sh_offset;

    // Iterate over the symbol table entries
    Elf64_Sym *symtab = (Elf64_Sym *)(file + symtab_header->sh_offset);
    // ... (Get string table and section headers as before) ...

    for (int i = 0; i < symtab_header->sh_size / sizeof(Elf64_Sym); i++) {
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_OBJECT && 
            symtab[i].st_shndx != SHN_UNDEF && 
            symtab[i].st_shndx != SHN_ABS &&
            symtab[i].st_shndx == getSectionHeaderIndex(header,file,".data") &&
            ELF64_ST_VISIBILITY(symtab[i].st_other) == STV_DEFAULT) {  // Check if in .data section 

            // Get the data section header
            Elf64_Shdr *data_section_header = getSectionHeader(header, file, ".data");

            // Calculate the offset of the variable from the start of the .data section
            Elf64_Off variable_offset = symtab[i].st_value - data_section_header->sh_addr;
            //printf("Variable offset: %lu\n", variable_offset);

            // Get the variable's value
            int *variable_ptr = (int *)(file + data_section_header->sh_offset + variable_offset);
            int variable_value = *variable_ptr;

            char *var_name = strtab + symtab[i].st_name;

            printf("Variable name: %s, value: %d\n", var_name, variable_value);

            int changed_value = 22;

            // Seek to the location of the variable within the .data section
            int seek_result = lseek(fd, data_section_header->sh_offset + variable_offset, SEEK_SET);

            size_t write_count = write(fd, &changed_value, sizeof(int));
            if (write_count != sizeof(int)) {
                perror("write");
            }

            
            
            
        }   
    }
}




int main(int argc, char *argv[]) {
    
    printf("parameter: %s\n", argv[1]);
    printf("elf path: %s\n", argv[2]);

    char *param = argv[1];
    char *elf_path = argv[2];

    // Open the file
    int fd = open(argv[2], O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    // Get file size
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return 1;
    }

    // Map the file into memory
    char *file = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    //preberem glavo
    Elf64_Ehdr *header = (Elf64_Ehdr *)file;

    // Preverimo, ali je datoteka res ELF datoteka
    if (header->e_ident[0] != 0x7f || header->e_ident[1] != 'E' || header->e_ident[2] != 'L' || header->e_ident[3] != 'F') {
        printf("Datoteka ni ELF datoteka\n");
        close(fd);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0)
    {
        printf("Magic: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", header->e_ident[i]);
        }
        printf("\n");
        printf("Class: %s\n", getElfClass(header->e_ident[4]));
        printf("Data: %s\n", getDataEncoding(header->e_ident[5]));
        printf("Version: %d (current)\n", header->e_version);
        printf("OS/ABI: %s\n", getOSABI(header->e_ident[7]));
        printf("ABI Version: %d\n", header->e_ident[8]);
        printf("Type: %s\n", getElfType(header->e_type));
        printf("Machine: %s\n", getMachineType(header->e_machine));
        printf("Version: 0x%x\n", header->e_version);
        printf("Entry point address: 0x%lx\n", header->e_entry);
        printf("Start of program headers: %lu (bytes into file)\n", header->e_phoff);
        printf("Start of section headers: %lu (bytes into file)\n", header->e_shoff);
        printf("Flags: 0x%x\n", header->e_flags);
        printf("Size of this header: %d (bytes)\n", header->e_ehsize);
        printf("Size of program headers: %d (bytes)\n", header->e_phentsize);
        printf("Number of program headers: %d\n", header->e_phnum);
        printf("Size of section headers: %d (bytes)\n", header->e_shentsize);
        printf("Number of section headers: %d\n", header->e_shnum);
        printf("Section header string table index: %d\n", header->e_shstrndx);
        close(fd);

    }
    else if (strcmp(argv[1], "-l") == 0)
    {
        
        Elf64_Shdr *symtab_header  = getSectionHeader(header, file, ".symtab");
        printf("Offset: %lu\n", symtab_header->sh_offset);

        //print_symtab_functions(symtab_header, header, file);
        print_symtab_variables(symtab_header, header, file, fd);

    }

    else if (strcmp(argv[1], "-c") == 0)
    {

        /* code */
    }
    
    // Unmap the file
    if (munmap(file, sb.st_size) == -1) {
        perror("munmap");
        close(fd);
        return 1;
    }
    // Close the file
    close(fd);

    return 0;
}
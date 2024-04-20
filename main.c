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

int main(int argc, char *argv[]) {
    
    printf("parameter: %s\n", argv[1]);
    printf("elf path: %s\n", argv[2]);

    char *param = argv[1];
    char *elf_path = argv[2];

    /*
    //odpremo datoteko v binarnem načinu
    FILE *file = fopen(argv[2], "rb");
    if (file == NULL) {
        perror("Napaka pri odpiranju datoteke");
        return 1;
    }
    */
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
    Elf64_Ehdr header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        perror("Napaka pri branju glave datoteke");
        close(fd);
        return 1;
    }

    // Preverimo, ali je datoteka res ELF datoteka
    if (header.e_ident[0] != 0x7f || header.e_ident[1] != 'E' || header.e_ident[2] != 'L' || header.e_ident[3] != 'F') {
        printf("Datoteka ni ELF datoteka\n");
        fclose(file);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0)
    {
        printf("Magic: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", header.e_ident[i]);
        }
        printf("\n");
        printf("Class: %s\n", getElfClass(header.e_ident[4]));
        printf("Data: %s\n", getDataEncoding(header.e_ident[5]));
        printf("Version: %d (current)\n", header.e_version);
        printf("OS/ABI: %s\n", getOSABI(header.e_ident[7]));
        printf("ABI Version: %d\n", header.e_ident[8]);
        printf("Type: %s\n", getElfType(header.e_type));
        printf("Machine: %s\n", getMachineType(header.e_machine));
        printf("Version: 0x%x\n", header.e_version);
        printf("Entry point address: 0x%lx\n", header.e_entry);
        printf("Start of program headers: %lu (bytes into file)\n", header.e_phoff);
        printf("Start of section headers: %lu (bytes into file)\n", header.e_shoff);
        printf("Flags: 0x%x\n", header.e_flags);
        printf("Size of this header: %d (bytes)\n", header.e_ehsize);
        printf("Size of program headers: %d (bytes)\n", header.e_phentsize);
        printf("Number of program headers: %d\n", header.e_phnum);
        printf("Size of section headers: %d (bytes)\n", header.e_shentsize);
        printf("Number of section headers: %d\n", header.e_shnum);
        printf("Section header string table index: %d\n", header.e_shstrndx);
        fclose(file);

    }
    else if (strcmp(argv[1], "-l") == 0)
    {
        // 1. Locate the section header string table section
        Elf64_Shdr shstrtab_header;
        fseek(file, header.e_shoff + (header.e_shentsize * header.e_shstrndx), SEEK_SET);
        fread(&shstrtab_header, sizeof(shstrtab_header), 1, file);

        // 2. Read the string table
        char* strtab = malloc(shstrtab_header.sh_size);
        fseek(file, shstrtab_header.sh_offset, SEEK_SET);
        fread(strtab, shstrtab_header.sh_size, 1, file);
        size_t strtab_size = shstrtab_header.sh_size;

        
        //unsigned long first_section_offset = header.e_shoff+header.e_shentsize;
        unsigned long second_section_offset = header.e_shoff+(header.e_shentsize *8);
        //printf("Before fseek: Offset value: %lu\n", first_section_offset);
        //drugi section
        if (fseek(file, second_section_offset, SEEK_SET) != 0) {
            perror("Error seeking to the beginning of the second section");
            fclose(file);
            return 1;
        }

        Elf64_Shdr second_section;
        if (fread(&second_section, sizeof(second_section), 1, file) != 1) {
            perror("Error reading the header of the second section");
            fclose(file);
            return 1;
        }
        printf("Size of second section : %lu\n", second_section.sh_size);
        printf("Name of second section : %u\n", second_section.sh_name);

        if (second_section.sh_name < strtab_size) {
            const char* section_name = strtab + second_section.sh_name;
            printf("Name of second section : %s\n", section_name);
        } else {
            printf("Invalid section name index.\n");
        }


    }

    else if (param == "-c")
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
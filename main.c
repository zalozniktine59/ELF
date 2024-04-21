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

// Struktura ELFHeader, ki ustreza glavi ELF datoteke
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
    unsigned short shstrndx; // section header string table index (torej samo kater section po vrsti je)
*/

// Struktura ELFSection, ki predstavlja vnos v tabeli sekcij
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
    // zracunam offset za section header string table
    // e_shoff je offset za section header table, e_shentsize je size per section header, e_shstrndx je index na katerem mestu je 
    size_t shstrtab_header_offset = header->e_shoff + (header->e_shentsize * header->e_shstrndx);
    // Nastavim pointer na zacetek section header string table
    Elf64_Shdr *shstrtab_header = (Elf64_Shdr *)((char *)file + shstrtab_header_offset);
    // Nastavim pointer na zacetek dejanskega string table
    char *shstrtab = (char *)file + shstrtab_header->sh_offset;
    // Iteriram cez vse section headerje
    for (int i = 0; i < header->e_shnum; i++) {
        // zracunam offset za trenutni section header
        size_t section_offset = header->e_shoff + (header->e_shentsize * i);
        
        // Nastavim pointer na trenutni section header
        Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)file + section_offset);
        
        // Preverim ce je ime sectiona enako iskanemu
        //shstrab je zacetek string tabele in dodam sh_name offset, da dobim kje se zacne ime sectiona
        if (strcmp(shstrtab + section_header->sh_name, section_name) == 0) {
            return i;
        }
    }
    return -1;
}

Elf64_Shdr* getSectionHeader(Elf64_Ehdr *header, char *file, const char *section_name) {

    // zracunam offset za section header string table
    // e_shoff je offset za section header table, e_shentsize je size per section header, e_shstrndx je index na katerem mestu je 
    size_t shstrtab_header_offset = header->e_shoff + (header->e_shentsize * header->e_shstrndx);
    // Nastavim pointer na zacetek section header string table
    Elf64_Shdr *shstrtab_header = (Elf64_Shdr *)((char *)file + shstrtab_header_offset);
    // Nastavim pointer na zacetek dejanskega string table
    char *shstrtab = (char *)file + shstrtab_header->sh_offset;
    // Iteriram cez vse section headerje
    for (int i = 0; i < header->e_shnum; i++) {
        // zracunam offset za trenutni section header
        size_t section_offset = header->e_shoff + (header->e_shentsize * i);
        
        // Nastavim pointer na trenutni section header
        Elf64_Shdr *section_header = (Elf64_Shdr *)((char *)file + section_offset);
        
        // Preverim ce je ime sectiona enako iskanemu
        //shstrab je zacetek string tabele in dodam sh_name offset, da dobim kje se zacne ime sectiona
        if (strcmp(shstrtab + section_header->sh_name, section_name) == 0) {
            return section_header;
        }
    }
    return NULL;
}
void elf_27286_glava(char *file){
    Elf64_Ehdr *header = (Elf64_Ehdr *)file;
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

}
void elf_27286_simboli(Elf64_Shdr *symtab_header, Elf64_Ehdr *header, char *file) {
    // Shranim pointer na string table section header
    // strtab_header je header za string tabelo
    // header je zacetek elf datoteke (damo v char da se lahko premikamo po bajtih)
    // pristejemo header->e_shoff, da pridemo do zacetka section headerjev
    // pristejemo symtab_header->sh_link * header->e_shentsize, sh_link je index v symtab_headerju, ki pove kje je posebna string tabela od symtab_headerja
    // nato pa še pomnožim z e_shentsize, ki je velikost enega section headerja
    // torej tabela nizov od tabele simbolov(symtab) je samo en section
    Elf64_Shdr *strtab_header = (Elf64_Shdr *)((char *)header + header->e_shoff + (symtab_header->sh_link * header->e_shentsize));
    // Nastavim pointer na zacetek string tabele od tabele simbolov
    char *strtab = file + strtab_header->sh_offset;

    // iteriram cez vse vnose v simbolni tabeli
    Elf64_Sym *symtab = (Elf64_Sym *)(file + symtab_header->sh_offset);
    // grem cez vse simbole
    for (long unsigned int i = 0; i < symtab_header->sh_size / sizeof(Elf64_Sym); i++) {
        // prevemim ce je tip simbola funkcija in ce je velikost vecja od 20
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC && symtab[i].st_size > 20) {
            // dobim ime funkcije
            char *func_name = strtab + symtab[i].st_name;
            // dobim velikost funkcije
            int func_size = symtab[i].st_size;
            printf("%s, velikosti: %i B\n", func_name, func_size);
        }
    }
}
void elf_27286_menjaj(Elf64_Shdr *symtab_header, Elf64_Ehdr *header, char *file, int fd, char* variables[], int variables_size) {
    // Dobim string table od simbolov
    Elf64_Shdr *strtab_header = (Elf64_Shdr *)((char *)header + header->e_shoff + (symtab_header->sh_link * header->e_shentsize));
    char *strtab = file + strtab_header->sh_offset;

    // Iteriram cez vse vnose v simbolni tabeli
    Elf64_Sym *symtab = (Elf64_Sym *)(file + symtab_header->sh_offset);
    // Grem cez vse simbole
    for (long unsigned int i = 0; i < symtab_header->sh_size / sizeof(Elf64_Sym); i++) {
        // Preverim ce je tip simbola objekt in ce ni undefined in ce ni absoluten
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_OBJECT && 
            symtab[i].st_shndx != SHN_UNDEF && 
            symtab[i].st_shndx != SHN_ABS &&
            symtab[i].st_shndx == getSectionHeaderIndex(header,file,".data") && // preverim ce je v .data sectionu
            ELF64_ST_VISIBILITY(symtab[i].st_other) == STV_DEFAULT) // preverim ce je simbol globalen (default)
            {  

            // Dobim section header od .data sectiona
            Elf64_Shdr *data_section_header = getSectionHeader(header, file, ".data");
            char *var_name = strtab + symtab[i].st_name;
            // Preverim ce je ime spremenljivke v arrayu imen spremenljivk
            int found = 0;
            for (int j = 0; j < variables_size; j++) {
                if (strcmp(var_name, variables[j]) == 0) {
                    found = 1;
                    break;
                }
            }
            // Je v arrayu imen spremenljivk
            if (found) {
                // zracunam offset od zacetka .data sectiona
                // - je zato ker računam offset od začetka sectiona
                Elf64_Off variable_offset = symtab[i].st_value - data_section_header->sh_addr;

                // Dobim vrednost spremenljivke
                int *variable_ptr = (int *)(file + data_section_header->sh_offset + variable_offset);
                int variable_value = *variable_ptr;
                // Dobim ime spremenljivke
                char *var_name = strtab + symtab[i].st_name;

                int changed_value = variable_value + 2;

                // Premaknem se na lokacijo spremenljivke v .data sectionu
                lseek(fd, data_section_header->sh_offset + variable_offset, SEEK_SET);

                // Zapišem novo vrednost spremenljivke
                size_t write_count = write(fd, &changed_value, sizeof(int));
                if (write_count != sizeof(int)) {
                    perror("write");
                }
                printf("Variable %s changed from %d to %d\n", var_name, variable_value, changed_value);
            }
        }   
    }
}


int main(int argc, char *argv[]) {
    int number_of_variables = argc - 3;

    char *variables[number_of_variables];
    for (int i = 0; i < number_of_variables; i++) {
        variables[i] = argv[i + 3];
    }
    // Odprem datoteko
    int fd = open(argv[2], O_RDWR);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    // Dobim velikost
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return 1;
    }

    // Shranim vsebino datoteke v ram
    char *file = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    //preberem glavo
    Elf64_Ehdr *header = (Elf64_Ehdr *)file;
    // dobim section header string tabele
    Elf64_Shdr *symtab_header  = getSectionHeader(header, file, ".symtab");

    // Preverimo, ali je datoteka res ELF datoteka
    if (header->e_ident[0] != 0x7f || header->e_ident[1] != 'E' || header->e_ident[2] != 'L' || header->e_ident[3] != 'F') {
        printf("Datoteka ni ELF datoteka\n");
        close(fd);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0)
    {
        elf_27286_glava(file);
    }
    else if (strcmp(argv[1], "-l") == 0)
    {
        elf_27286_simboli(symtab_header, header, file);
    }

    else if (strcmp(argv[1], "-c") == 0)
    {
        elf_27286_menjaj(symtab_header, header, file, fd, variables, number_of_variables);
    }
    
    // Unmap
    if (munmap(file, sb.st_size) == -1) {
        perror("munmap");
        close(fd);
        return 1;
    }
    close(fd);

    return 0;
}
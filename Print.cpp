#include "PEFILE.h"
using namespace std;

PEFILE::PEFILE(char* _NAME, FILE* _Ppefile) {
	NAME = _NAME;
	Ppefile = _Ppefile;

    ParseFile();
}

// in ra thông tin cơ bản về file
void PEFILE::PrintFile() {
	printf("FILE %s\n", NAME);
}

void PEFILE::PrintDOSHeader() {
	printf("Magic    : 0x%X\n", PEFILE_DOS_HEADER.e_magic);
	printf("Cblp     : 0x%X\n", PEFILE_DOS_HEADER.e_cblp);
	printf("Cp       : 0x%X\n", PEFILE_DOS_HEADER.e_cp);
    printf("Crlc     : 0x%X\n", PEFILE_DOS_HEADER.e_crlc);
    printf("Cparhdr  : 0x%X\n", PEFILE_DOS_HEADER.e_cparhdr);
    printf("Minalloc : 0x%X\n", PEFILE_DOS_HEADER.e_minalloc);
    printf("Maxalloc : 0x%X\n", PEFILE_DOS_HEADER.e_maxalloc);
    printf("SS       : 0x%X\n", PEFILE_DOS_HEADER.e_ss);
    printf("SP       : 0x%X\n", PEFILE_DOS_HEADER.e_sp);
    printf("Csum     : 0x%X\n", PEFILE_DOS_HEADER.e_csum);
    printf("IP       : 0x%X\n", PEFILE_DOS_HEADER.e_ip);
    printf("CS       : 0x%X\n", PEFILE_DOS_HEADER.e_cs);
    printf("Lfarlc   : 0x%X\n", PEFILE_DOS_HEADER.e_lfarlc);
    printf("Ovlo     : 0x%X\n", PEFILE_DOS_HEADER.e_ovno); 
	for (int i = 0; i < 4; i++) {
        printf("Res[%d]   : 0x%X\n", i, PEFILE_DOS_HEADER.e_res[i]);
    }
	printf("Oemid    : 0x%X\n", PEFILE_DOS_HEADER.e_oemid);
    printf("Oeminfo  : 0x%X\n", PEFILE_DOS_HEADER.e_oeminfo);
	for (int i = 0; i < 10; i++) {
        printf("Res2[%d]  : 0x%X\n", i, PEFILE_DOS_HEADER.e_res2[i]);
    }
	printf("Lfanew   : 0x%X\n", PEFILE_DOS_HEADER.e_lfanew); 
}

void PEFILE::PrintNTHeaders() {
	printf(" PE Signature: 0x%X\n", PEFILE_NT_HEADERS.Signature);

	printf("\n File Header:\n");
    printf("  Machine                 : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.Machine);
    printf("  Number of sections      : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.NumberOfSections);
    printf("  TimeDateStamp           : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.TimeDateStamp);
    printf("  PointerToSymbolTable    : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.PointerToSymbolTable);
    printf("  NumberOfSymbols         : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.NumberOfSymbols);
    printf("  Size of optional header : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.SizeOfOptionalHeader);
    printf("  Characteristics         : 0x%X\n", PEFILE_NT_HEADERS.FileHeader.Characteristics);

    printf("\n Optional Header:\n");
    printf("  Magic                        : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.Magic);
    printf("  MajorLinkerVersion           : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion           : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode                   : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData        : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData      : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfUninitializedData);
    printf("  AddressOfEntryPoint          : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode                   : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.BaseOfCode);
    printf("  ImageBase                    : 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.ImageBase);
    printf("  SectionAlignment             : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SectionAlignment);
    printf("  FileAlignment                : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion  : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion  : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion            : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion            : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion        : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion        : %d\n", PEFILE_NT_HEADERS.OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue            : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.Win32VersionValue);
    printf("  SizeOfImage                  : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders                : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeaders);
    printf("  CheckSum                     : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.CheckSum);
    printf("  Subsystem                    : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.Subsystem);
    printf("  DllCharacteristics           : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.DllCharacteristics);
    printf("  SizeOfStackReserve           : 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit            : 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve            : 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit             : 0x%llX\n", PEFILE_NT_HEADERS.OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags                  : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes          : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.NumberOfRvaAndSizes);

	printf("\n Data Directories:\n");
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        printf(" + Directory[%d]:\n", i);
        printf("   RVA  : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[i].VirtualAddress);
        printf("   Size : 0x%X\n", PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[i].Size);
    }
}

void PEFILE::PrintSectionHeaders() {
	for (int i = 0; i < PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
		printf(" + %.8s:\n", PEFILE_SECTION_HEADERS[i].Name);
		printf("    VirtualSize          : 0x%X\n", PEFILE_SECTION_HEADERS[i].Misc.VirtualSize);
		printf("    VirtualAddress       : 0x%X\n", PEFILE_SECTION_HEADERS[i].VirtualAddress);
		printf("    SizeOfRawData        : 0x%X\n", PEFILE_SECTION_HEADERS[i].SizeOfRawData);
		printf("    PointerToRawData     : 0x%X\n", PEFILE_SECTION_HEADERS[i].PointerToRawData);
		printf("    PointerToRelocations : 0x%X\n", PEFILE_SECTION_HEADERS[i].PointerToRelocations);
		printf("    PointerToLinenumbers : 0x%X\n", PEFILE_SECTION_HEADERS[i].PointerToLinenumbers);
		printf("    NumberOfRelocations  : 0x%X\n", PEFILE_SECTION_HEADERS[i].NumberOfRelocations);
		printf("    NumberOfLinenumbers  : 0x%X\n", PEFILE_SECTION_HEADERS[i].NumberOfLinenumbers);
		printf("    Characteristics      : 0x%X\n\n", PEFILE_SECTION_HEADERS[i].Characteristics);
	}
}

void PEFILE::PrintImportTable() {
    for (int i = 0; i < PEFILE_IMPORT_TABLE.size(); i++) {
        DWORD Name_offset = GetOffset(PEFILE_IMPORT_TABLE[i].Name);
        fseek(Ppefile, Name_offset, SEEK_SET);

        string dll_name;
        char ch;
        while (fread(&ch, 1, 1, Ppefile)) { 
            if (ch == '\0') break; 
            dll_name.push_back(ch);
        }
        printf(" + %s:\n", dll_name.c_str());

        printf("    Characteristics    : 0x%X\n", PEFILE_IMPORT_TABLE[i].Characteristics);
        printf("    OriginalFirstThunk : 0x%X\n", PEFILE_IMPORT_TABLE[i].OriginalFirstThunk);
        printf("    TimeDateStamp      : 0x%X\n", PEFILE_IMPORT_TABLE[i].TimeDateStamp);
        printf("    ForwarderChain     : 0x%X\n", PEFILE_IMPORT_TABLE[i].ForwarderChain);
        printf("    Name               : 0x%X\n", PEFILE_IMPORT_TABLE[i].Name);
        printf("    FirstThunk         : 0x%X\n", PEFILE_IMPORT_TABLE[i].FirstThunk);
        printf("\n");

        DWORD ILT_offset = GetOffset(PEFILE_IMPORT_TABLE[i].OriginalFirstThunk);
        int entry_count = 0;

        while(true) {
            ULONGLONG raw_ILT = 0; // đọc ILT chiếm 64 bit
            fseek(Ppefile, (ILT_offset + (entry_count * sizeof(ULONGLONG    ))), SEEK_SET);
            fread(&raw_ILT, sizeof(ULONGLONG), 1, Ppefile);

            if (!raw_ILT) break;
            printf("    + Entry:\n");

            if (!(raw_ILT >> 63)) { // đọc bit 63 để check cờ
                WORD hint_value;
                DWORD rva = (DWORD)(raw_ILT & 0xFFFFFFFFu); // đọc 32 bit đầu
                DWORD hint_offset = GetOffset(rva);
                
                fseek(Ppefile, hint_offset, SEEK_SET);
                fread(&hint_value, sizeof(WORD), 1, Ppefile);
                
                string Name;
                char ch;
                    while (fread(&ch, 1, 1, Ppefile)) { 
                    if (ch == '\0') break; 
                    Name.push_back(ch);
                }
                
                printf("      Hint RVA: 0x%X\n", rva);
                printf("      Hint: 0x%X\n", hint_value);
                printf("      Name: %s\n", Name.c_str());
            } else {
                WORD Ordinal = (WORD)(raw_ILT & 0xFFFF);
                printf("      Ordinal: 0x%X\n", Ordinal);
            }
            entry_count++;
        }
    }
}

void PEFILE::PrintBaseRelocations() {
    int sz_counter = sizeof(IMAGE_BASE_RELOCATION);

    for (int i = 0; i < PEFILE_BASERELOC_TABLE.size(); i++) {
        DWORD RVA, block_size;
		int ENTRIES;
        
        DWORD BASE_RELOC_ADDR = GetOffset(PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
        RVA = PEFILE_BASERELOC_TABLE[i].VirtualAddress;
		block_size = PEFILE_BASERELOC_TABLE[i].SizeOfBlock;
		ENTRIES = (block_size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        printf("    Block 0x%X: \n", i);
		printf("    Page RVA: 0x%X\n", RVA);
		printf("    Block size: 0x%X\n", block_size);
		printf("    Number of entries: 0x%X\n", ENTRIES);
		printf("    Entries:\n");

        for (int i = 0; i < ENTRIES; i++) {

			BASE_RELOC_ENTRY entry;

			int offset = (BASE_RELOC_ADDR + sz_counter + (i * sizeof(WORD)));

			fseek(Ppefile, offset, SEEK_SET);
			fread(&entry, sizeof(WORD), 1, Ppefile);

			printf("    + Value: \n");
			printf("      Relocation Type: 0x%X\n", entry.TYPE);
			printf("      Offset: 0x%X\n", entry.OFFSET);

		}
		sz_counter += block_size;
    }
}

void PEFILE::PrintInfo() {
	printf("\n");
	
	printf("File Info \n");	
	PrintFile();
	printf("\n");

	printf("DOS Header \n");
	PrintDOSHeader();
	printf("\n");

	printf("NT Headers \n");
	PrintNTHeaders();
	printf("\n");

	printf("Section Headers \n");
	PrintSectionHeaders();
	printf("\n");

    printf("Import Table \n");
	PrintImportTable();
	printf("\n");

    printf("Base Relocations \n");
	PrintBaseRelocations();
}
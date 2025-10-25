#include <iostream>
#include <fstream>
#include <windows.h>
#include "PEFILE.h"
using namespace std;

void PEFILE::ParseDOSHeader() {
    fread(&PEFILE_DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, Ppefile); // đọc toàn bộ thông tin về dos header vào biến
}

void PEFILE::ParseNTHeaders() {
    fseek(Ppefile, PEFILE_DOS_HEADER.e_lfanew, SEEK_SET); //Nhảy đến vị trí NT header
	fread(&PEFILE_NT_HEADERS, sizeof(PEFILE_NT_HEADERS), 1, Ppefile); // nhận giá trị NT Header

    PEFILE_EXPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[0];
	PEFILE_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[1];
	PEFILE_RESOURCE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[2];
	PEFILE_EXCEPTION_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[3];
	PEFILE_SECURITY_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[4];
	PEFILE_BASERELOC_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[5];
	PEFILE_DEBUG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[6];
	PEFILE_ARCHITECTURE_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[7];
	PEFILE_GLOBALPTR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[8];
	PEFILE_TLS_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[9];
	PEFILE_LOAD_CONFIG_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[10];
	PEFILE_BOUND_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[11];
	PEFILE_IAT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[12];
	PEFILE_DELAY_IMPORT_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[13];
	PEFILE_COM_DESCRIPTOR_DIRECTORY = PEFILE_NT_HEADERS.OptionalHeader.DataDirectory[14];
}

void PEFILE::ParseSectionHeaders() {
    PEFILE_SECTION_HEADERS.resize(PEFILE_NT_HEADERS.FileHeader.NumberOfSections); // tao mang dong luu het section
	for (int i = 0; i < PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
		int offset = (PEFILE_DOS_HEADER.e_lfanew + sizeof(PEFILE_NT_HEADERS)) + (i * IMAGE_SIZEOF_SECTION_HEADER);
		fseek(Ppefile, offset, SEEK_SET);
		fread(&PEFILE_SECTION_HEADERS[i], IMAGE_SIZEOF_SECTION_HEADER, 1, Ppefile);
	}
}

DWORD PEFILE::GetOffset(DWORD RVA) {
	int id_section = 0;
	for (int i = 0; i < PEFILE_NT_HEADERS.FileHeader.NumberOfSections; i++) {
		if (PEFILE_SECTION_HEADERS[i].VirtualAddress <= RVA && RVA < (PEFILE_SECTION_HEADERS[i].VirtualAddress + PEFILE_SECTION_HEADERS[i].Misc.VirtualSize)) {
			id_section = i;
			break;
		}
	}

	DWORD offset = RVA - PEFILE_SECTION_HEADERS[id_section].VirtualAddress + PEFILE_SECTION_HEADERS[id_section].PointerToRawData;
	return offset;
}

void PEFILE::ParseImportDirectory() {
	DWORD import_directory_offset = GetOffset(PEFILE_IMPORT_DIRECTORY.VirtualAddress);
	
	while(true) {
		IMAGE_IMPORT_DESCRIPTOR tmp;
		int offset = import_directory_offset + (PEFILE_IMPORT_TABLE.size() * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		fseek(Ppefile, offset, SEEK_SET);
		fread(&tmp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, Ppefile);

		if (tmp.Name == 0x00000000 &&tmp.FirstThunk == 0x00000000) {
			break;
		}
		
		PEFILE_IMPORT_TABLE.push_back(tmp);
	}
}

void PEFILE::ParseBaseReloc() {
	DWORD basereloc_directory_offset = GetOffset(PEFILE_BASERELOC_DIRECTORY.VirtualAddress);
	int basreloc_size_counter = 0;

	while(true) {
		IMAGE_BASE_RELOCATION tmp;
		int offset = basereloc_directory_offset + basreloc_size_counter;
		fseek(Ppefile, offset, SEEK_SET);
		fread(&tmp, sizeof(IMAGE_BASE_RELOCATION), 1, Ppefile);

		if (tmp.VirtualAddress == 0x00000000 &&tmp.SizeOfBlock == 0x00000000) {
			break;
		}
		
		PEFILE_BASERELOC_TABLE.push_back(tmp);
		basreloc_size_counter += tmp.SizeOfBlock;
	}
}

void PEFILE::ParseFile() {
    ParseDOSHeader();
    ParseNTHeaders();
    ParseSectionHeaders();
	ParseImportDirectory();
	ParseBaseReloc();
}
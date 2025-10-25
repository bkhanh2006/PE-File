#include <iostream>
#include <fstream>
#include <windows.h>
#include "PEFILE.h"
using namespace std;

int main(int argc, char* argv[]){
    freopen("out.txt", "w", stdout);

    if (argc < 2) {
		printf("Nhap sai dinh dang\n");
		return 1;
	}

    FILE * PpeFile;
    fopen_s(&PpeFile, argv[1], "rb");

    if (PpeFile == NULL) {
        printf("Khong the mo file \n");
        return 1;
    }

    IMAGE_DOS_HEADER DOS_HEADER;
    fread(&DOS_HEADER, sizeof(IMAGE_DOS_HEADER), 1, PpeFile);

    if (DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE) { 
        printf("Khong phai file PE \n");
        fclose(PpeFile);
        return 1;
    }

    fseek(PpeFile, DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
    // nhảy đến OPTIONAL_HEADER của NT HEADER
    WORD magic; 
    fread(&magic, sizeof(WORD), 1, PpeFile);
    rewind(PpeFile); // reset lại PpeFile

   if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) { 
        printf("file 64-bit \n");
        PEFILE PeFile_1(argv[1], PpeFile);
        PeFile_1.PrintInfo();
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf("file 32-bit \n");
    } else {
        printf("Khong phai file PE\n");
        fclose(PpeFile);
        return 1;
    }

    if (PpeFile != NULL) {
        fclose(PpeFile);
    }

    return 0;
}
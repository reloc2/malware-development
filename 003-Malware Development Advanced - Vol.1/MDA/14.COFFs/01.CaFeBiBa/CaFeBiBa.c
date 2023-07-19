/*

 Red Team Operator course code template
 CaFeBiBa (pron. ka-feh-bee-bah) - COFF parsing engine
 
 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: COFFLoader (by Kevin Haubris/@kev169)

*/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <strsafe.h>
#include "CaFeBiBa.h"


// quick and dirty way to print data of unknown type
int printSecData(char * c, size_t size) {
	char temp[17];												// 16-char line + 1 null byte
	int i = 0;

	while ( i < size) {
		printf("%.8x:  ", i);									// print offset of the bytes
		for (int p = 0 ; p < 16 ; p++) {						// print hex bytes, 16 per line
			if (p == 8) printf(" ");							// put extra space in the middle of the line
			printf("%.2hhx ", *c);								// print the current byte
			if (*c >= 32 && *c <= 126) temp[p] = *c;			// if current byte is printable, save it as-is
			else temp[p] = '.';									// otherwise, save it as a dot
			if ( ++i >= size) {									// if in the last line...
				for ( int a = 0; a < (16 - p) * 2 - 1; a++)		// add extra space between hex values and ascii string
					printf(" ");
				break;
			}
			c++;												// take the next byte
		}
		temp[16] = '\0';										// add the trailing null byte
		printf("%#20s\n\t", temp);								// and print the line as a string
		memset(temp, 0, 16);			
	}
	
	return 0;
}


// main COFF parsing function
int ParseCOFF(unsigned char * COFF_data) {
    COFF_FILE_HEADER * 	coff_header_ptr = NULL;
    COFF_SECTION *		coff_sect_ptr = NULL;
    COFF_RELOCATION * 	coff_reloc_ptr = NULL;
    COFF_SYMBOL * 		coff_sym_ptr = NULL;
	BOOL prn = FALSE;

	// Step 1. Get a pointer to COFF header and print all the fields
	coff_header_ptr = (COFF_FILE_HEADER *) COFF_data;
	printf("[+] Machine: %#x\n", coff_header_ptr->Machine);
	printf("[+] Number Of Sections: %d\n", coff_header_ptr->NumberOfSections);
	printf("[+] Time/Date Stamp: %#x\n", coff_header_ptr->TimeDateStamp);
	printf("[+] Pointer To Symbol Table: %#x\n", coff_header_ptr->PointerToSymbolTable);
	printf("[+] Number Of Symbols: %d\n", coff_header_ptr->NumberOfSymbols);
	printf("[+] Size Of Optional Header: %#x\n", coff_header_ptr->SizeOfOptionalHeader);
	printf("[+] Characteristics: %#x\n", coff_header_ptr->Characteristics);
	
	// Step 1a. Allocate some extra memory for internal parsing structures (not necessary, will be used during loading)
	size_t MemSectionsSize = sizeof(COFF_MEM_SECTION) * coff_header_ptr->NumberOfSections;
	COFF_MEM_SECTION * MemSections = calloc(coff_header_ptr->NumberOfSections, sizeof(COFF_MEM_SECTION));
	if (!MemSections) {
		printf("[!] ERROR! Aligned memory allocation failed!\n");
		return -1;
	}
	printf("\n[+] Allocated some space for parsed sections (%#llx | %d)\n", MemSections, MemSectionsSize);
	
	// Step 2. Parse and print information about all COFF sections, including data and relocations
	printf("\n[+] Starting to parse all sections:");
	for (int i = 0 ; i < coff_header_ptr->NumberOfSections ; i++) {
		// get pointer to current section to parse
		coff_sect_ptr = (COFF_SECTION *)(COFF_data + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * i));
		
		// if the section is not empty, save the data in the internal structure
		if (coff_sect_ptr->SizeOfRawData > 0) {
			MemSections[i].Counter = i;
			StringCchCopyA(MemSections[i].Name, strlen(coff_sect_ptr->Name) + 1, coff_sect_ptr->Name);
			MemSections[i].Name[8] = '\0';
			MemSections[i].SizeOfRawData = coff_sect_ptr->SizeOfRawData;
			MemSections[i].PointerToRawData = coff_sect_ptr->PointerToRawData;
			MemSections[i].PointerToRelocations = coff_sect_ptr->PointerToRelocations;
			MemSections[i].NumberOfRelocations = coff_sect_ptr->NumberOfRelocations;
			MemSections[i].Characteristics = coff_sect_ptr->Characteristics;
			MemSections[i].InMemorySize = MemSections[i].SizeOfRawData  + (0x1000 - MemSections[i].SizeOfRawData % 0x1000); // align to page size
			MemSections[i].InMemoryAddress = NULL;   // VirtuAlloc(...)
			
			prn = TRUE;
		}
		
		// print the values of the current section
		printf("\n[+] Section #%d:\n", i);
		printf("\tName: %s\n", prn ? MemSections[i].Name : coff_sect_ptr->Name);
		printf("\tVirtual Size: %#x\n", coff_sect_ptr->VirtualSize);
		printf("\tVirtual Address: %#x\n", coff_sect_ptr->VirtualAddress);
		printf("\tSize Of Raw Data: %d\n", prn ? MemSections[i].SizeOfRawData : coff_sect_ptr->SizeOfRawData);
		printf("\tPointer To Raw Data: %#x\n", prn ? MemSections[i].PointerToRawData : coff_sect_ptr->PointerToRawData);
		printf("\tPointer To Relocations: %#x\n", prn ? MemSections[i].PointerToRelocations : coff_sect_ptr->PointerToRelocations);
		printf("\tPointer To Line Numbers: %#x\n", coff_sect_ptr->PointerToLineNumbers);
		printf("\tNumber Of Relocations: %d\n", prn ? MemSections[i].NumberOfRelocations : coff_sect_ptr->NumberOfRelocations);
		printf("\tNumber Of Line numbers: %d\n", coff_sect_ptr->NumberOfLinenumbers);
		printf("\tCharacteristics: %#x\n", prn ? MemSections[i].Characteristics : coff_sect_ptr->Characteristics);
		
		prn = FALSE;

		// also, if section contains any data -> print it out for a quick glance
		if (coff_sect_ptr->SizeOfRawData > 0 && coff_sect_ptr->PointerToRawData > 0) {
			printf("\n\tSection\'s data:\n\t");
			printSecData((char *) COFF_data + coff_sect_ptr->PointerToRawData, (size_t) coff_sect_ptr->SizeOfRawData);
		}

		// now work on all relocations in the section, if there are any		
		if (MemSections[i].NumberOfRelocations != 0) {
			printf("\n\tSection's relocations:\n");
			for (int x = 0 ; x < MemSections[i].NumberOfRelocations ; x++) {
				coff_reloc_ptr = (COFF_RELOCATION *) (COFF_data + MemSections[i].PointerToRelocations + sizeof(COFF_RELOCATION) * x);
				printf("\tReloc: %#4d  | ", x);
				printf("  VAddress:%#9x  |", coff_reloc_ptr->VirtualAddress);
				printf("  SymTab Index:%#5d  |", coff_reloc_ptr->SymbolTableIndex);
				printf("  Type:%#5x\n", coff_reloc_ptr->Type);
			}
		}
	}

	// Step 3. Parse and print the entire Symbol Table
	coff_sym_ptr = (COFF_SYMBOL *) (COFF_data + coff_header_ptr->PointerToSymbolTable);
	char * 	coff_strings_ptr = (char *)((COFF_data + coff_header_ptr->PointerToSymbolTable) + coff_header_ptr->NumberOfSymbols * sizeof(COFF_SYMBOL));
	printf("\n\n[+] COFF SYMBOL TABLE\n\n");
	printf("------+--------------+-----------+--------+---------------+-------------------\n");
	printf("%#4s  |%#9s     |%#9s  |%#6s  |%#14s |%#7s", "No.", "VALUE","SECTION", "TYPE", "STORAGE CLASS", "NAME\n");
	printf("------+--------------+-----------+--------+---------------+-------------------\n");
	for (int i = 0 ; i < coff_header_ptr->NumberOfSymbols ; i++) {
		printf("%#4d  |", i);
		printf("%#12x  |", coff_sym_ptr[i].Value);
		printf("%#9x  |", coff_sym_ptr[i].SectionNumber);
		printf("%#6.4d  |", coff_sym_ptr[i].Type);
		printf("%#13d  |", coff_sym_ptr[i].StorageClass);
		if (coff_sym_ptr[i].SectionNumber == 0 && coff_sym_ptr[i].StorageClass == 0)	// according to COFF docs this is IMAGE_SYM_UNDEFINED
			printf(" <undefined>");
		else											// otherwise, get a string from the Strings Table
		if (coff_sym_ptr[i].first.Zeros != 0) {			// check if the string is in the Strings Table
			char n[10];									// if not, make sure that a string from ShortName is ending with null byte
			StringCchCopyA(n, strlen(coff_sym_ptr[i].first.ShortName) + 1, coff_sym_ptr[i].first.ShortName);
			n[8] = '\0';
			printf(" %s", n);
		}
		else
		printf(" %s", (char *)(coff_strings_ptr + coff_sym_ptr[i].first.Offset));
		printf("\n");
	}
	printf("------+--------------+-----------+--------+---------------+-------------------\n");
	
	printf("\n\n[+] FINISHED!\n");	
	
	// cleanup
	VirtualFree(MemSections, 0, MEM_RELEASE);
	
	return 0;
}


int main(int argc, char * argv[]) {
	
	if (argc < 2) {
		printf("[!] ERROR! Run: %s <path_2_file>\n", argv[0]);
		return -1;
	}

	// map the COFF file into memory for parsing
	HANDLE COFFfile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (COFFfile == INVALID_HANDLE_VALUE) {
			printf("[!] Could not open file: %s\n", argv[1]);
			return -1;
	}

	HANDLE FileMapping = CreateFileMapping(COFFfile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (FileMapping == NULL) {
			printf("[!] Could not call CreateFileMapping (%#x)\n", GetLastError());
			return -1;
	}

	LPVOID COFF_data = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (COFF_data == NULL) {
			printf("[!] Could not call MapViewOfFile (%#x)\n", GetLastError());
			return -1;
	}

	// if file is mapped, proceed with parsing...
	int result = ParseCOFF((unsigned char *) COFF_data);
	if (result)
		printf("[!] ERROR parsing the input file! Exiting...\n");

	// clean up before saying Good-bye!
	UnmapViewOfFile(COFF_data);
	CloseHandle(FileMapping);
	CloseHandle(COFFfile);

	return 0;
}

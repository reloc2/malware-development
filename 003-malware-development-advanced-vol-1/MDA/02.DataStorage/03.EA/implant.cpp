/*

 Red Team Operator course code template
 Registry storage
 
 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: Regin / ZeroAccess / Adam "Hexacorn"

*/
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _FILE_FULL_EA_INFORMATION {
  ULONG  NextEntryOffset;
  UCHAR  Flags;
  UCHAR  EaNameLength;
  USHORT EaValueLength;
  CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef NTSTATUS (NTAPI * ZwQueryEaFile_t)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	BOOLEAN          ReturnSingleEntry,
	PVOID            EaList,
	ULONG            EaListLength,
	PULONG           EaIndex,
	BOOLEAN          RestartScan
);

typedef NTSTATUS (NTAPI * ZwSetEaFile_t)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length
);

ZwQueryEaFile_t pZwQueryEaFile	= NULL;
ZwSetEaFile_t pZwSetEaFile		= NULL;

#define STATUS_NO_EAS_ON_FILE 			0xC0000052
#define STATUS_EAS_NOT_SUPPORTED 		0xC000004F
#define STATUS_INSUFFICIENT_RESOURCES	0xC000009A
#define STATUS_EA_LIST_INCONSISTENT		0x80000014
#define FILE_NEED_EA					0x00000080


// quick and dirty way to print data of unknown type
int printData(char * c, size_t size) {
	char temp[17];												// 16-char line + 1 null byte
	int i = 0;

	printf("\t");
	while ( i < size) {
		printf("%.8x:  ", i);									// print offset of the bytes
		for (int j = 0 ; j < 16 ; j++) {						// print hex bytes, 16 per line
			if (j == 8) printf(" ");							// put extra space in the middle of the line
			printf("%.2hhx ", *c);								// print the current byte
			if (*c >= 32 && *c <= 126) temp[j] = *c;			// if current byte is printable, save it as-is
			else temp[j] = '.';									// otherwise, save it as a dot
			if ( ++i >= size) {									// if in the last line...
				for ( int a = 0; a < (16 - j) * 2 - 1; a++)		// add extra space between hex values and ascii string
					printf(" ");
				break;
			}
			c++;												// take the next byte
		}
		temp[16] = '\0';										// add the trailing null byte
		printf("%#20s\n\t", temp);								// and print the line as a string
		memset(temp, 0, 16);			
	}
	printf("\n");
	
	return 0;
}


// print the data returned from ZwQueryEaFile()
int PrintEA(char * buff, size_t buff_size) {
	char * p = NULL;
	char Name[256] = { 0 };
	ULONG NextEntryOffset = 0;
	UCHAR Flags = 0;
	UCHAR EaNameLength = 0;
	USHORT EaValueLength = 0;
	CHAR * EaName;
	
	// loop through all the attributes
	p = buff;
	while(TRUE) {
		// get appropriate FILE_FULL_EA_INFORMATION fields
		NextEntryOffset = (ULONG) *p;
		Flags = (UCHAR) *(p + 4);
		EaNameLength = (UCHAR) *(p + 5);
		EaValueLength = (USHORT) *(p + 6);
		EaName = (CHAR *) (p + 8);
		memset(Name, 0, 256);
		memcpy(Name, EaName, EaNameLength);

		// and print them out
		printf("\t- NextEntryOffset = %#lx\n", NextEntryOffset);
		printf("\t- Flags = %#x\n", Flags);
		printf("\t- EaNameLength = %x\n", EaNameLength);
		printf("\t- EaValueLength = %d\n", EaValueLength);
		printf("\t- EaName = %s\n", EaName);	
		if (EaValueLength > 0) {
			printf("\t- EaValue:\n\n");
			printData((p + 8 + EaNameLength + 1), EaValueLength);
		}		
		
		// if the last attribute, abandon the ship
		if (NextEntryOffset == 0)
			break;
		
		// otherwise, proceed
		p += NextEntryOffset;
		printf("\n");
	}

	return 0;
}



// read in all EA attributes
int ReadEA(HANDLE src, char * buf, size_t buf_size) {
	IO_STATUS_BLOCK IoStatusBlock;
	
    NTSTATUS status = pZwQueryEaFile(src, &IoStatusBlock, (PFILE_FULL_EA_INFORMATION) buf, buf_size, FALSE, NULL, 0, NULL, TRUE);
	if (status == STATUS_NO_EAS_ON_FILE) {
		printf("[!] There's no EA attribute on the file\n");
		return 0;
	}
	if (status != 0) {
		printf("[!] Could not read file's EA records (%x)\n", status);
		return -1;		
	}	

	return 0;
}


// write a single EA attribute
int WriteEA(HANDLE src, char * EAname, char * EAvalue, size_t EAvalue_size) {
	IO_STATUS_BLOCK IoStatusBlock;
	char space[0xffff + 256] = { 0 };
	FILE_FULL_EA_INFORMATION dumpEA = { 0 };

	// setup the EA information structure
	dumpEA.NextEntryOffset = 0;
	dumpEA.Flags = 0;
	dumpEA.EaNameLength = (UCHAR) strlen(EAname);
	dumpEA.EaValueLength = (USHORT) EAvalue_size;
    strcpy_s(dumpEA.EaName, dumpEA.EaNameLength + 1, EAname);
	memcpy(dumpEA.EaName + dumpEA.EaNameLength + 1, EAvalue, dumpEA.EaValueLength);
	
	// send it to the kernel
	NTSTATUS status = pZwSetEaFile(src, &IoStatusBlock, (PVOID) &dumpEA, sizeof(FILE_FULL_EA_INFORMATION) + dumpEA.EaNameLength + 1 + dumpEA.EaValueLength);
	if (status != 0) {
		printf("[!] Error writing EA (%x)\n", status);
		return -1;
	}
	return 0;
}


int main(int argc, char *argv[]) {

	
	char * srcfile = argv[1];
	char Eaname[] = "SECRETZ";
	char EAvalue[] = "MIGHTY SECRET SAUCE";
	size_t EAvalue_size = strlen(EAvalue);
	//char EAvalue[] = { 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee, 0xcc, 0xaa, 0xff, 0xee };
	//size_t EAvalue_size = sizeof(EAvalue);
	
	if (argc < 2) {
		printf("[!] Missing argument. Run: %s <file>\n", argv[0]);
		return -1;
	}

	// resolve the function pointers
	pZwQueryEaFile = (ZwQueryEaFile_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwQueryEaFile");
	pZwSetEaFile = (ZwSetEaFile_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwSetEaFile");
	
	if (pZwQueryEaFile == NULL || pZwSetEaFile == NULL) {
		printf("[!] Could not resolve Zw API calls.\n");
		return -1;		
	}

	// open the target file
	HANDLE fileSrc = CreateFile(srcfile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (fileSrc == INVALID_HANDLE_VALUE) {
		printf("[!] Could not open file: %s\n", srcfile);
		return -1;
	}

	// create a new EA record
	printf("[+] Saving data inside EA record of %s\n", srcfile);
	if (WriteEA(fileSrc, Eaname, EAvalue, EAvalue_size))
		return -1;

	// extract and print EAs
	char * Buffer = (char *) malloc(0x1000);
	printf("[+] Reading EA record\n");	
	if (ReadEA(fileSrc, Buffer, 0x1000))
		return -1;

	printData(Buffer, 0x50);
	PrintEA(Buffer, 0x1000);
	
	free(Buffer);
	CloseHandle(fileSrc);
	
	return 0;
}

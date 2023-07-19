/*

 Red Team Operator course code template
 Remote modules enumeration with EnumProcessModulesEx
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Microsoft

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

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
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;		// might be used to allocate enough memory for hMods

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
        return -1;
	
	printf("[+] Modules found:\n");
	printf("\tBASE ADDRESS\t\tMODULE PATH\n");
	printf("  =================================================================================\n");
	// get all modules addresses, both 32- and 64-bit
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (int i = 0 ; i < (cbNeeded / sizeof(HMODULE)) ; i++) {
            char szModName[MAX_PATH];

			// translate modules base address to full module path
            if (GetModuleFileNameEx(hProcess, hMods[i], (LPSTR) szModName, sizeof(szModName) / sizeof(TCHAR))) {
                printf("%#21llx\t%s\n", hMods[i], szModName);
            }
        }
    }
	CloseHandle(hProcess);

	return 0;
}


int main(void) {

	int pid = FindTarget("notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);
	
	if (pid != 0)
		ListModules(pid);

	return 0;
}

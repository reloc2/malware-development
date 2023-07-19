/*

 Red Team Operator course code template
 Remote modules enumeration with VirtualQueryEx
 
 author: reenz0h (twitter: @SEKTOR7net)

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
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    char * base = NULL;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL)
        return -1;

	// query the process memory starting from NULL
    while (VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
         char szModName[MAX_PATH];

		// only focus on the base address regions
 		if ((mbi.AllocationBase == mbi.BaseAddress) && (mbi.AllocationBase != NULL)) {
			if (GetModuleFileNameEx(hProcess, (HMODULE) mbi.AllocationBase, (LPSTR) szModName, sizeof(szModName) / sizeof(TCHAR)))
				printf("%#21llx\t%s\n", mbi.AllocationBase, szModName);
        }
		// check the next region
		base += mbi.RegionSize;
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

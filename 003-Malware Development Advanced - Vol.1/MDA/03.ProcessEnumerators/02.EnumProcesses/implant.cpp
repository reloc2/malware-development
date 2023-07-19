/*

 Red Team Operator course code template
 Process enumeration with EnumProcesses()
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Microsoft

*/
#include <windows.h>
#include <stdio.h>
#include <psapi.h>

int FindTarget(const char * procname) {

	int pid = 0;
	DWORD Procs[1024], bytesReturned, NumOfProcesses;
	TCHAR szProcessName[MAX_PATH];
	
	// Get the list of process identifiers.
	if ( !EnumProcesses(Procs, sizeof(Procs), &bytesReturned) ) 
        return 0;
	
	// Calculate how many process identifiers were returned.
    NumOfProcesses = bytesReturned / sizeof(DWORD);

    for (int i = 0; i < NumOfProcesses; i++ ) {
        if (Procs[i] != 0) {
			// Get a handle to the process.
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Procs[i]);

			// and find the one we're looking for
			if (hProc != NULL) {
				HMODULE hModule;

				if (EnumProcessModules(hProc, &hModule, sizeof(hModule), &bytesReturned)) {
					GetModuleBaseName(hProc, hModule, (LPSTR) szProcessName, sizeof(szProcessName)/sizeof(TCHAR));
					if (lstrcmpiA(procname, szProcessName) == 0) {
						pid = Procs[i];
						break;
					}
				}
			}
			CloseHandle(hProc);
        }
    }
	
    return pid;
}



int main(void) {

	int pid = FindTarget("notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);

	return 0;
}

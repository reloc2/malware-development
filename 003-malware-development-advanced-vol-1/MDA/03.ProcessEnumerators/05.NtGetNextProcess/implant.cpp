/*

 Red Team Operator course code template
 Process enumeration with NtGetNextProcess()
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Wen Jia Liu
 
*/
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef NTSTATUS (NTAPI * NtGetNextProcess_t)(
	_In_ HANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Flags,
	_Out_ PHANDLE NewProcessHandle
	);
	
int FindTarget(const char * procname) {

	int pid = 0;
	HANDLE currentProc = NULL;
	char procNameTemp[MAX_PATH];
	
	// resolve function address
	NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");

	// loop through all processes
	while (!pNtGetNextProcess(currentProc, MAXIMUM_ALLOWED, 0, 0, &currentProc)) {
		
		GetProcessImageFileNameA(currentProc, procNameTemp, MAX_PATH);
		//printf("procname = %s\n", PathFindFileName((LPCSTR) procNameTemp));
		if (lstrcmpiA(procname, PathFindFileName((LPCSTR) procNameTemp)) == 0) {
			pid = GetProcessId(currentProc);
			break;
		}
	}
	
    return pid;
}


int main(void) {

	int pid = FindTarget("notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);

	return 0;
}

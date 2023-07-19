/*

 Red Team Operator course code template
 Process enumeration with NtQuerySystemInformation()
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Wen Jia Liu

*/
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

#define SystemProcessInformation 5

typedef NTSTATUS (WINAPI * NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

int FindTarget(WCHAR * procname) {

	int pid = 0;
	PVOID buffer = NULL;
	DWORD bufSize = 0;
	
	// resolve function address
	NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");

	// get initial buffer size to allocate
	pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemProcessInformation, 0, 0, &bufSize);
	
	if (bufSize == 0)
		return -1;
	
	// allocate appropriate buffer for process information
	if (buffer = VirtualAlloc(0, bufSize, MEM_COMMIT, PAGE_READWRITE)) {
		
		SYSTEM_PROCESS_INFORMATION * sysproc_info = (SYSTEM_PROCESS_INFORMATION *) buffer;
		if (!pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS) SystemProcessInformation, buffer, bufSize, &bufSize)) {
			while (TRUE) {
				//printf("procname = %S\n", sysproc_info->ImageName.Buffer);
				if (lstrcmpiW(procname, sysproc_info->ImageName.Buffer) == 0) {
					pid = (int) sysproc_info->UniqueProcessId;
					break;
				}				
				
				// are we done?
				if (!sysproc_info->NextEntryOffset)
					break;
				
				// check next entry
				sysproc_info = (SYSTEM_PROCESS_INFORMATION *)((ULONG_PTR) sysproc_info + sysproc_info->NextEntryOffset);
			}
		}
		else
			return -3;
	}
	else
		return -2;
	
	
	VirtualFree(buffer, bufSize, MEM_RELEASE);
	
    return pid;
}



int main(void) {

	int pid = FindTarget(L"notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);

	return 0;
}

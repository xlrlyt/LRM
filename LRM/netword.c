#include "network.h"


WSK_REGISTRATION g_wskReg;
WSK_PROVIDER_NPI g_wskPrv;
WSK_CLIENT_DISPATCH g_wskDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

enum
{
	INITIALIZING,
	INITIALIZED,
	DEINITIALIZED,
	DEINITIALIZING
};

LONG g_wskLock = DEINITIALIZED;



NTSTATUS initWsk() {
	if (InterlockedCompareExchange(&g_wskLock, INITIALIZING, DEINITIALIZED) != DEINITIALIZED) {
		return STATUS_ABANDONED;
	}
	WSK_CLIENT_NPI wskClient = {0};
	wskClient.ClientContext = NULL;
	//set client dispatch
	wskClient.Dispatch = &g_wskDispatch;
	NTSTATUS status = WskRegister(&wskClient, &g_wskReg);
	if (!NT_SUCCESS(status)) {
		InterlockedExchange(&g_wskLock, DEINITIALIZED);
		xLog("WskRegister Failed! Unscience");
		return status;
	}
	status = WskCaptureProviderNPI(&g_wskReg, WSK_NO_WAIT, &g_wskPrv);
	if (!NT_SUCCESS(status)) {
		InterlockedExchange(&g_wskLock, DEINITIALIZED);
		WskDeregister(&g_wskReg);
		xLog("WskCaptureProviderNPI Failed!");
		return status;
	}
	xLog("Wsk Init Success");
	InterlockedExchange(&g_wskLock, INITIALIZED);
	return status;
}

void freeWsk() {
	if (InterlockedCompareExchange(&g_wskLock, DEINITIALIZED, INITIALIZED) != INITIALIZED) {
		return;
	}
	WskReleaseProviderNPI(&g_wskReg);
	WskDeregister(&g_wskReg);
	xLog("Wsk Released");
}
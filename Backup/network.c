/*
Module: network.c

Description: A simple winsock tools

Author: lolita

Waring: I will ignore all allocate failure, if there are no enough resource, just go die


*/



#include "network.h"
#include "xlog.h"


WSK_REGISTRATION g_wskReg;
WSK_PROVIDER_NPI g_wskPrv;
WSK_CLIENT_DISPATCH g_wskDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };
//60s timeout
LARGE_INTEGER timeout2;

enum
{
	INITIALIZING,
	INITIALIZED,
	DEINITIALIZED,
	DEINITIALIZING
};

LONG g_wskLock = DEINITIALIZED;


NTSTATUS NetworkCompleteRt(
	IN PDEVICE_OBJECT pDevice,
	IN PIRP pIrp,
	IN PKEVENT pEvent //the context
) {
	UNREFERENCED_PARAMETER(pIrp);
	UNREFERENCED_PARAMETER(pDevice);
	if (pEvent != NULL) {
		KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
	}
	return STATUS_MORE_PROCESSING_REQUIRED;
}

//allocate irp , init&set irp event
NTSTATUS InitWskIrp(
	OUT PIRP* ppIrp,
	OUT PKEVENT pEvent
) {
	
	*ppIrp = IoAllocateIrp(1, FALSE);
	KeInitializeEvent(pEvent, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(*ppIrp, NetworkCompleteRt, pEvent, TRUE, TRUE, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS initWsk() {

	if (InterlockedCompareExchange(&g_wskLock, INITIALIZING, DEINITIALIZED) != DEINITIALIZED) {
		return STATUS_ABANDONED;
	}
	timeout2.QuadPart = -10 * 1000 * 1000;
	timeout2.QuadPart *= 60;
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

//To use this function to connect, you need to create socket and bind a any address first, deperated
NTSTATUS ConnectWskSocket(
	IN PWSK_SOCKET pSocket,
	IN PSOCKADDR pAddr
) {
	if (g_wskLock != INITIALIZED) {
		return STATUS_INVALID_PARAMETER;
	}
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIRP pIrp = NULL;
	KEVENT kEvent;
	InitWskIrp(&pIrp, &kEvent);
	
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pSocket->Dispatch)->WskConnect(
		pSocket,
		pAddr,
		NULL,
		pIrp
	);
	if (status = STATUS_PENDING) {
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
		status = pIrp->IoStatus.Status;
	}
	IoFreeIrp(pIrp);
	return status;
}
//Will return a socket ro
NTSTATUS ConnectWsk(
	PWSK_SOCKET* ppSocket,
	PSOCKADDR pAddr
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIRP pIrp;
	KEVENT kEvent;
	
	InitWskIrp(&pIrp, &kEvent);
	SOCKADDR localAddr = { 0 };
	localAddr.sa_family = pAddr->sa_family;
	status = g_wskPrv.Dispatch->WskSocketConnect(
		g_wskPrv.Client, /* Client             */
		SOCK_STREAM,    /* SocketType         */
		IPPROTO_TCP,    /* Protocol           */
		&localAddr,       /* LocalAddress       */
		pAddr,			/* RemoteAddress      */
		0,              /* Flags              */
		NULL,           /* SocketContext      */
		NULL,           /* Dispatch           */
		NULL,           /* OwningProcess      */
		NULL,           /* OwningThread       */
		NULL,           /* SecurityDescriptor */
		pIrp			/* Irp                */
	);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
		status = pIrp->IoStatus.Status;
	}

	if (!NT_SUCCESS(status)) {
		IoFreeIrp(pIrp);
		return status;
	}

	*ppSocket = pIrp->IoStatus.Information;
	IoFreeIrp(pIrp);
	return status;

}


NTSTATUS CloseSocket(
	IN PWSK_SOCKET pSocket
) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIRP pIrp = NULL;
	KEVENT kEvent;
	InitWskIrp(&pIrp, &kEvent);
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pSocket->Dispatch)->WskCloseSocket(
		pSocket,
		pIrp
	);
	if (status = STATUS_PENDING) {
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
		status = pIrp->IoStatus.Status;
	}
	IoFreeIrp(pIrp);
	return status;
}

NTSTATUS SendWsk(
	PWSK_SOCKET pSocket,
	PVOID pData,
	ULONG dataLen
) {
	WSK_BUF wskBuf;
	PIRP pIrp;
	NTSTATUS status;
	KEVENT kEvent;
	InitWskIrp(&pIrp, &kEvent);
	//set MDF
	wskBuf.Offset = 0;
	wskBuf.Mdl = IoAllocateMdl(pData, dataLen, FALSE, FALSE, NULL); //need to free
	MmBuildMdlForNonPagedPool(wskBuf.Mdl);
	wskBuf.Length = dataLen;
	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pSocket->Dispatch)->WskSend(
		pSocket,
		&wskBuf,
		NULL,
		pIrp
	);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, 0);
		status = pIrp->IoStatus.Status;
	}
	IoFreeIrp(pIrp);
	IoFreeMdl(wskBuf.Mdl);
	return status;

}

NTSTATUS RecvWsk(
	PWSK_SOCKET pSocket,
	PVOID pData,
	ULONG dataLen,
	PULONG recvd
) {
	NTSTATUS status;
	PIRP pIrp;
	KEVENT kEvent;
	WSK_BUF wskBuf = { 0 };

	InitWskIrp(&pIrp, &kEvent);
	wskBuf.Length = dataLen;
	wskBuf.Mdl = IoAllocateMdl(pData, dataLen, FALSE, FALSE, NULL);
	wskBuf.Offset = 0;

	MmBuildMdlForNonPagedPool(wskBuf.Mdl);

	status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pSocket->Dispatch)->WskReceive(
		pSocket,
		&wskBuf,
		0,
		pIrp
	);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&kEvent, Executive, KernelMode, FALSE, NULL);
		status = pIrp->IoStatus.Status;
	}
	ULONG recvLen = pIrp->IoStatus.Information;
	if (!NT_SUCCESS(status)) {
		recvLen = -1;
	}
	IoFreeIrp(pIrp);
	IoFreeMdl(wskBuf.Mdl);
	if (recvd != NULL) {
		*recvd = recvLen;
	}
	return status;

	

}

void network_test() {
	
}
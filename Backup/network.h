#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wsk.h>

NTSTATUS initWsk();
void freeWsk();

NTSTATUS ConnectWsk(
	PWSK_SOCKET* ppSocket,
	PSOCKADDR pAddr
);
NTSTATUS CloseSocket(
	IN PWSK_SOCKET pSocket
);
NTSTATUS SendWsk(
	PWSK_SOCKET pSocket,
	PVOID pData,
	ULONG dataLen
);

NTSTATUS RecvWsk(
	PWSK_SOCKET pSocket,
	PVOID pData,
	ULONG dataLen,
	PULONG recvd
);
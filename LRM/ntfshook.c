#include "ntfshook.h"
#include "xlog.h"
PFILE_OBJECT pFile_ntfs = NULL;
PDEVICE_OBJECT pDev_ntfs = NULL;
PDRIVER_OBJECT pDrv_ntfs = NULL;
PDRIVER_DISPATCH OldIrpMjCreate = NULL;

ULONG pendingOperation = 0;

PUNICODE_STRING pProtectFileName;
PUNICODE_STRING pReplaceFileName;

NTSTATUS myNtfsCreate(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp
) {
	InterlockedIncrement(&pendingOperation);
	UNICODE_STRING oldUnicodeString;
	PIO_STACK_LOCATION stack;
	NTSTATUS status;
	stack = IoGetCurrentIrpStackLocation(pIrp);
	PFILE_OBJECT FileObject = NULL;
	PFILE_OBJECT pNPFO;
	BOOLEAN rp = 0;
	if (stack->MajorFunction == IRP_MJ_CREATE) {
		//fuckit
		FileObject = stack->FileObject;
		if (FileObject != NULL) {
			//xLogW(&FileObject->FileName);
			LONG res = RtlCompareUnicodeString(
				&FileObject->FileName,
				pProtectFileName,
				TRUE
			);
			if (res == 0) {
				rp = 1;
				//pNPFO = (PFILE_OBJECT)ExAllocatePool(NonPagedPool, sizeof(FILE_OBJECT));
				//memcpy(pNPFO, FileObject, sizeof(FILE_OBJECT));
				memcpy(&oldUnicodeString, &FileObject->FileName, sizeof(UNICODE_STRING));
				//FileObject->FileName
				//oldUnicodeString.Buffer = FileObject->FileName.Buffer;
				//oldUnicodeString.Length = FileObject->FileName.Length;
				//oldUnicodeString.MaximumLength = FileObject->FileName.MaximumLength;
				//FileObject->FileName.Buffer = pReplaceFileName->Buffer;
				//FileObject->FileName.Length = pReplaceFileName->Length;
				//FileObject->FileName.MaximumLength = pReplaceFileName->MaximumLength;
				memcpy(&FileObject->FileName, pReplaceFileName, sizeof(UNICODE_STRING));
				xLog("replaced a request");
			}
		}
	}
	status = OldIrpMjCreate(pDeviceObject, pIrp);
	if (rp) {
		stack->FileObject = FileObject;
		//ExFreePool()
		memcpy(&FileObject->FileName, &oldUnicodeString, sizeof(UNICODE_STRING));
		//FileObject->FileName.Buffer = oldUnicodeString.Buffer;
		//FileObject->FileName.Length = oldUnicodeString.Length;
		//FileObject->FileName.MaximumLength = oldUnicodeString.MaximumLength;
	}
	
	InterlockedDecrement(&pendingOperation);
	return status;
}



NTSTATUS hookNtfs(PUNICODE_STRING protectFileName, PUNICODE_STRING replaceFileName) {
	NTSTATUS       ntStatus;
	//  UNICODE_STRING deviceNameUnicodeString;
	//  UNICODE_STRING deviceLinkUnicodeString;        
	UNICODE_STRING deviceTCPUnicodeString;
	WCHAR deviceTCPNameBuffer[] = L"\\Ntfs";


	RtlInitUnicodeString(&deviceTCPUnicodeString, deviceTCPNameBuffer);
	ntStatus = IoGetDeviceObjectPointer(&deviceTCPUnicodeString, FILE_READ_DATA, &pFile_ntfs, &pDev_ntfs);
	if (!NT_SUCCESS(ntStatus))
	{
		xLog("hook failed");
		return ntStatus;
	}
	xLog("tcp hook success");
	pDrv_ntfs = pDev_ntfs->DriverObject;

	OldIrpMjCreate = pDrv_ntfs->MajorFunction[IRP_MJ_CREATE];
	CHAR msg[32];
	RtlStringCbPrintfA(msg, 32, "old addr: %p", OldIrpMjCreate);
	xLog(msg);

	if (OldIrpMjCreate)
		InterlockedExchange((PLONG)&pDrv_ntfs->MajorFunction[IRP_MJ_CREATE], (LONG)myNtfsCreate);
	RtlStringCbPrintfA(msg, 32, "new addr: %p", pDrv_ntfs->MajorFunction[IRP_MJ_CREATE]);
	xLog(msg);
	
	pProtectFileName = protectFileName;
	pReplaceFileName = replaceFileName;

	return STATUS_SUCCESS;

}

NTSTATUS unhookntfs()
{
	xLog("unhook ntfs");
	if (OldIrpMjCreate)
		InterlockedExchange((PLONG)&pDrv_ntfs->MajorFunction[IRP_MJ_CREATE], (LONG)OldIrpMjCreate);
	if (pFile_ntfs != NULL)
		ObDereferenceObject(pFile_ntfs);
	pFile_ntfs = NULL;

	return STATUS_SUCCESS;
}
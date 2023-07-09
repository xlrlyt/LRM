typedef NTSTATUS EndSetFileAttributes(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    Irp->UserIosb->Status = Irp->IoStatus.Status;
    Irp->UserIosb->Information = Irp->IoStatus.Information;
    KeSetEvent(Irp->UserEvent, 0, FALSE);
    IoFreeIrp(Irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS ResetFileAttributes(HANDLE FileHandle)
{
    NTSTATUS status;
    PDEVICE_OBJECT pDevObj = NULL;
    PIRP pIrp = NULL;
    KEVENT Event;
    IO_STATUS_BLOCK ios = { 0 };
    FILE_BASIC_INFORMATION BasicInfo;
    PIO_STACK_LOCATION IrpSp;
    status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, &FileObject, NULL);
    if (NT_SUCCESS(status))
    {
        pDevObj = IoGetRelatedDeviceObject(FileObject);//穿透
        pIrp = IoAllocateIrp(pDevObj->StackSize, TRUE);
        if (pIrp)
        {
            KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
            RtlZeroMemory(&BasicInfo, sizeof(BasicInfo));
            BasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            pIrp->AssociatedIrp.SystemBuffer = (PVOID)&BasicInfo;
            pIrp->UserEvent = &Event;
            pIrp->UserIosb = &ios;
            pIrp->Tail.Overlay.OriginalFileObject = FileObject;
            pIrp->Tail.Overlay.Thread = KeGetCurrentThread();
            pIrp->RequestorMode = 0;
            IrpSp = IoGetNextIrpStackLocation(pIrp);
            IrpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
            IrpSp->DeviceObject = pDevObj;
            IrpSp->FileObject = FileObject;
            IrpSp->Parameters.SetFile.Length = sizeof(BasicInfo);
            IrpSp->Parameters.SetFile.FileInformationClass = FileBasicInformation;
            IrpSp->Parameters.SetFile.FileObject = FileObject;
            IrpSp->CompletionRoutine = EndSetFileAttributes;
            IrpSp->Context = NULL;
            IrpSp->Control = SL_INVOKE_ON_CANCEL | SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR;
            IoCallDriver(pDevObj, Irp);
            KeWaitForSingleObject(&Event, 0, KernelMode, FALSE, NULL);
            ObDereferenceObject(FileObject);
        }
        else
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (FileObject)
        ObDereferenceObject(FileObject);
    return status;
}

void UnlockFileThread(PVOID StartContext)
{
    CmpSetHandleProtection(&Ohfi, FALSE);
    if (StartContext)
        NtClose(StartContext);
    PsTerminateSystemThread(0);
}

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
}

NTSTATUS UnlockFile(PUNICODE_STRING FileDosPath)
{
    IO_STATUS_BLOCK IoStatusBlock = { 0 };
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;
    HANDLE FileHandle = NULL;
    PFILE_OBJECT FileObject = NULL;
    InitializeObjectAttributes(&oa, FileDosPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    //穿透IopCreateFile得到FileHandle
    status = ResetFileAttributes(FileHandle);
    if (NT_SUCCESS(status))
    {
        status = ObReferenceObjectByHandle(FileHandle, 0, *IoFileObjectType, KernelMode, &FileObject, NULL);
        if (NT_SUCCESS(status))
        {
            IopDeleteFile(FileObject);
            TryUnlockFile(FileObject);
            FileHandle = NULL;
            ObDereferenceObject(FileObject);
        }
    }
    else if (status == STATUS_DELETE_PENDING)
    {
        TryUnlockFile(FileObject);
        status = STATUS_SUCCESS;
        FileHandle = NULL;
    }
    if (FileHandle)
        ZwClose(FileHandle);
    return status;
}



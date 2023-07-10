/*
Module: xlog.c

Description: Log to file

Author: lolita

log

*/





#include "xlog.h"


HANDLE g_hLogFile = NULL;


void xLog(PCSTR logTextA) {
	if (PRODUCT_MODE) return;
	if (g_hLogFile == NULL) return;
	IO_STATUS_BLOCK ios;
	ZwWriteFile(g_hLogFile, NULL, NULL, NULL, &ios, logTextA, strlen(logTextA), NULL, NULL);
	ZwWriteFile(g_hLogFile, NULL, NULL, NULL, &ios, "\n", 1, NULL, NULL);
}


NTSTATUS InitLogFile() {
	if (PRODUCT_MODE) return STATUS_SUCCESS;
	NTSTATUS status;
	OBJECT_ATTRIBUTES obj;
	UNICODE_STRING logPath;
	IO_STATUS_BLOCK ios;
	RtlInitUnicodeString(&logPath, DRIVER_LOG_FILENAME);
	InitializeObjectAttributes(&obj, &logPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = IoCreateFile(&g_hLogFile,
		FILE_APPEND_DATA | SYNCHRONIZE,
		&obj,
		&ios,
		0,
		FILE_ATTRIBUTE_SYSTEM,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		CreateFileTypeNone,
		NULL,
		0
	);
	if (!NT_SUCCESS(status)) {
		g_hLogFile = NULL;
	}
	return status;
}
NTSTATUS CloseLogFile() {
	if (PRODUCT_MODE) return;
	if (g_hLogFile != NULL) {
		ZwClose(g_hLogFile);
	}
	g_hLogFile = NULL;
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
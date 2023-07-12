/*
Module: xlog.c

Description: Log to file

Author: lolita

log

*/





#include "xlog.h"


HANDLE g_hLogFile = NULL;


void xLog(PCSTR logTextA) {
	xLogL(logTextA, strlen(logTextA));
}

void xLogL(PCSTR logTextA, DWORD textLen) {
	if (PRODUCT_MODE) return;
	if (g_hLogFile == NULL) return;
	IO_STATUS_BLOCK ios;
	//KeEnterCriticalRegion();
	ZwWriteFile(g_hLogFile, NULL, NULL, NULL, &ios, logTextA, textLen, NULL, NULL);
	ZwWriteFile(g_hLogFile, NULL, NULL, NULL, &ios, "\n", 1, NULL, NULL);
	//KeLeaveCriticalRegion();
}

void xLogW(PUNICODE_STRING unicodeString) {
	ANSI_STRING ansiString;
	RtlUnicodeStringToAnsiString(&ansiString, unicodeString, TRUE);
	xLogL(ansiString.Buffer, ansiString.Length);
	RtlFreeAnsiString(&ansiString);
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
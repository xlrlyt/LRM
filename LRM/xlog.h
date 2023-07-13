#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wsk.h>
#include "config.h"
void xLog(PCSTR logTextA);
void xLogL(PCSTR logTextA, DWORD textLen);
void xLogW(PUNICODE_STRING unicodeString);
NTSTATUS InitLogFile();
NTSTATUS CloseLogFile();
void xLog_deperated(PCSTR logText);
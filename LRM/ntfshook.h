#include "internal.h"

extern ULONG pendingOperation;

NTSTATUS unhookntfs();
NTSTATUS hookNtfs(PUNICODE_STRING protectFileName, PUNICODE_STRING replaceFileName);
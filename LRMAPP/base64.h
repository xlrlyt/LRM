#pragma once

#ifndef _BASE64_H  
#define _BASE64_H  

#include <stdlib.h>  
#include <string.h>  

void base64_encode(const char* str, int len, char* result);

void base64_decode(const char* code, char* result, int* reslen);

#endif  

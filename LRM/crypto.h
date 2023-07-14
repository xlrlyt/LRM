#pragma once


#include "internal.h"
typedef unsigned char md5byte;
typedef unsigned int UWORD32;
typedef struct MD5Context {
	UWORD32 buf[4];
	UWORD32 bytes[2];
	UWORD32 in[16];
} MD5_CTX;
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, md5byte const *buf, unsigned int len);
void MD5Final(MD5_CTX *context, md5byte digest[16]);
void MD5Transform(UWORD32 buf[4], UWORD32 const in[16]);
typedef struct _rc4_state
{
	int x, y, m[256];
} rc4_state;

void rc4_setup(rc4_state *s, unsigned char *key, int length);
void rc4_crypt(rc4_state *s, unsigned char *data, int length);
void rc4enc(UCHAR* key, int kLength, UCHAR* data, int dLength);




typedef UCHAR uint8_t;
// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif

#ifndef CTR
#define CTR 1
#endif


#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYLEN 24
#define AES_keyExpSize 208
#else
#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176
#endif

typedef struct AES_ctx
{
	UCHAR RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
	UCHAR Iv[AES_BLOCKLEN];
#endif
} AES_CTX;

void AES_init_ctx(AES_CTX* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(AES_CTX* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(AES_CTX* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(const AES_CTX* ctx, uint8_t* buf);
void AES_ECB_decrypt(const AES_CTX* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(AES_CTX* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(AES_CTX* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CTR_xcrypt_buffer(AES_CTX* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)


unsigned char *CRYPT_DEShash(unsigned char *dst, const unsigned char *key, const unsigned char *src);
unsigned char *CRYPT_DESunhash(unsigned char *dst, const unsigned char *key, const unsigned char *src);
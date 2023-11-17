#pragma once

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define ASSERT assert
using BOOL = int;
#define TRUE 1
#define FALSE 0
using BYTE = unsigned char;
using WORD = unsigned short;
using DWORD = unsigned long;
using QWORD = unsigned __int64;
#define CDECL __cdecl

// ReverseEndian
void ReverseEndian32(void* dest, const void* src, DWORD len);
void ReverseEndian64(void* dest, const void* src, DWORD len);


// ROTATE
#define USE_ROTL 1

#if (USE_ROTAL==0)
#define ROTATE_L32(x,n)     ( _rotl(x,n) )
#define ROTATE_R32(x,n)     ( _rotr(x,n) )
#else
#define ROTATE_L32(x,n)     ( ((x) << (n)) | ((x) >> (32 - (n))) )
#define ROTATE_R32(x,n)     ( ((x) >> (n)) | ((x) << (32 - (n))) )
#endif

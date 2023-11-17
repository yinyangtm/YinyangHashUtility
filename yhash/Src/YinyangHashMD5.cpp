#include "YinyangHashMD5.h"


static void YinyangHashMD5Helper(const void* pBuffer, void* hash, DWORD len);

static constexpr DWORD hinit[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};


YinyangHashMD5::YinyangHashMD5()
{
	Initialize();
}

YinyangHashMD5::~YinyangHashMD5()
{
}

void YinyangHashMD5::Initialize()
{
	YinyangHashBase::Initialize();
	memcpy(m_pHash, hinit, 16);
}

void YinyangHashMD5::ComputeHashFinalHelper(void* msg_digest)
{
	BYTE buf[64];
	DWORD len;
	QWORD string_bit_len;

	memcpy(msg_digest, m_pHash, 16);

	len = m_dwRestLen;
	memcpy(buf, m_pRest, len);
	memset(buf + len, 0, 64 - len);
	buf[len] |= 0x80;

	if (len >= 56)
	{
		ComputeHashHelper(buf, msg_digest, 64);
		memset(buf, 0, 56);
	}

	string_bit_len = m_qwSrcLen * 8;
	memcpy(&buf[56], &string_bit_len, 8);

	ComputeHashHelper(buf, msg_digest, 64);
}

DWORD YinyangHashMD5::ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len)
{
	YinyangHashMD5Helper(pBuffer, msg_digest, len);
	return len % 64;
}

#define F(x, y, z)      (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z)      (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z)      ((x) ^ (y) ^ (z))
#define I(x, y, z)      ((y) ^ ((x) | (~(z))))

#define MD5_ROUND(a, b, fghi, k, s, i)      ( b + ROTATE_L32(a+fghi+w[k]+i,s) )
#define ROUND1(a, b, c, d, k, s, i)     a=MD5_ROUND(a, b, F(b,c,d), k, s, i);
#define ROUND2(a, b, c, d, k, s, i)     a=MD5_ROUND(a, b, G(b,c,d), k, s, i);
#define ROUND3(a, b, c, d, k, s, i)     a=MD5_ROUND(a, b, H(b,c,d), k, s, i);
#define ROUND4(a, b, c, d, k, s, i)     a=MD5_ROUND(a, b, I(b,c,d), k, s, i);


void YinyangHashMD5Helper(const void* pBuffer, void* hash, DWORD len)
{
	auto w = (DWORD*)pBuffer;
	auto h = static_cast<DWORD*>(hash);
	DWORD A, B, C, D;
	DWORD i = len / 64;

	A = h[0];
	B = h[1];
	C = h[2];
	D = h[3];

	while (i > 0)
	{
		ROUND1(A, B, C, D, 0, 7, 0xd76aa478)
		ROUND1(D, A, B, C, 1, 12, 0xe8c7b756)
		ROUND1(C, D, A, B, 2, 17, 0x242070db)
		ROUND1(B, C, D, A, 3, 22, 0xc1bdceee)
		ROUND1(A, B, C, D, 4, 7, 0xf57c0faf)
		ROUND1(D, A, B, C, 5, 12, 0x4787c62a)
		ROUND1(C, D, A, B, 6, 17, 0xa8304613)
		ROUND1(B, C, D, A, 7, 22, 0xfd469501)
		ROUND1(A, B, C, D, 8, 7, 0x698098d8)
		ROUND1(D, A, B, C, 9, 12, 0x8b44f7af)
		ROUND1(C, D, A, B, 10, 17, 0xffff5bb1)
		ROUND1(B, C, D, A, 11, 22, 0x895cd7be)
		ROUND1(A, B, C, D, 12, 7, 0x6b901122)
		ROUND1(D, A, B, C, 13, 12, 0xfd987193)
		ROUND1(C, D, A, B, 14, 17, 0xa679438e)
		ROUND1(B, C, D, A, 15, 22, 0x49b40821)

		ROUND2(A, B, C, D, 1, 5, 0xf61e2562)
		ROUND2(D, A, B, C, 6, 9, 0xc040b340)
		ROUND2(C, D, A, B, 11, 14, 0x265e5a51)
		ROUND2(B, C, D, A, 0, 20, 0xe9b6c7aa)
		ROUND2(A, B, C, D, 5, 5, 0xd62f105d)
		ROUND2(D, A, B, C, 10, 9, 0x02441453)
		ROUND2(C, D, A, B, 15, 14, 0xd8a1e681)
		ROUND2(B, C, D, A, 4, 20, 0xe7d3fbc8)
		ROUND2(A, B, C, D, 9, 5, 0x21e1cde6)
		ROUND2(D, A, B, C, 14, 9, 0xc33707d6)
		ROUND2(C, D, A, B, 3, 14, 0xf4d50d87)
		ROUND2(B, C, D, A, 8, 20, 0x455a14ed)
		ROUND2(A, B, C, D, 13, 5, 0xa9e3e905)
		ROUND2(D, A, B, C, 2, 9, 0xfcefa3f8)
		ROUND2(C, D, A, B, 7, 14, 0x676f02d9)
		ROUND2(B, C, D, A, 12, 20, 0x8d2a4c8a)

		ROUND3(A, B, C, D, 5, 4, 0xfffa3942)
		ROUND3(D, A, B, C, 8, 11, 0x8771f681)
		ROUND3(C, D, A, B, 11, 16, 0x6d9d6122)
		ROUND3(B, C, D, A, 14, 23, 0xfde5380c)
		ROUND3(A, B, C, D, 1, 4, 0xa4beea44)
		ROUND3(D, A, B, C, 4, 11, 0x4bdecfa9)
		ROUND3(C, D, A, B, 7, 16, 0xf6bb4b60)
		ROUND3(B, C, D, A, 10, 23, 0xbebfbc70)
		ROUND3(A, B, C, D, 13, 4, 0x289b7ec6)
		ROUND3(D, A, B, C, 0, 11, 0xeaa127fa)
		ROUND3(C, D, A, B, 3, 16, 0xd4ef3085)
		ROUND3(B, C, D, A, 6, 23, 0x04881d05)
		ROUND3(A, B, C, D, 9, 4, 0xd9d4d039)
		ROUND3(D, A, B, C, 12, 11, 0xe6db99e5)
		ROUND3(C, D, A, B, 15, 16, 0x1fa27cf8)
		ROUND3(B, C, D, A, 2, 23, 0xc4ac5665)

		ROUND4(A, B, C, D, 0, 6, 0xf4292244)
		ROUND4(D, A, B, C, 7, 10, 0x432aff97)
		ROUND4(C, D, A, B, 14, 15, 0xab9423a7)
		ROUND4(B, C, D, A, 5, 21, 0xfc93a039)
		ROUND4(A, B, C, D, 12, 6, 0x655b59c3)
		ROUND4(D, A, B, C, 3, 10, 0x8f0ccc92)
		ROUND4(C, D, A, B, 10, 15, 0xffeff47d)
		ROUND4(B, C, D, A, 1, 21, 0x85845dd1)
		ROUND4(A, B, C, D, 8, 6, 0x6fa87e4f)
		ROUND4(D, A, B, C, 15, 10, 0xfe2ce6e0)
		ROUND4(C, D, A, B, 6, 15, 0xa3014314)
		ROUND4(B, C, D, A, 13, 21, 0x4e0811a1)
		ROUND4(A, B, C, D, 4, 6, 0xf7537e82)
		ROUND4(D, A, B, C, 11, 10, 0xbd3af235)
		ROUND4(C, D, A, B, 2, 15, 0x2ad7d2bb)
		ROUND4(B, C, D, A, 9, 21, 0xeb86d391)

		A += h[0];
		B += h[1];
		C += h[2];
		D += h[3];
		h[0] = A;
		h[1] = B;
		h[2] = C;
		h[3] = D;
		w += 16;
		i--;
	}
}

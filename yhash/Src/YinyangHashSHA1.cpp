#include "YinyangHashSHA1.h"


static void YinyangHashSHA1Helper(const void* pBuffer, void* hash, DWORD len);

static constexpr DWORD hinit[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};


YinyangHashSHA1::YinyangHashSHA1()
{
	Initialize();
}

YinyangHashSHA1::~YinyangHashSHA1()
{
}

void YinyangHashSHA1::Initialize()
{
	YinyangHashBase::Initialize();
	memcpy(m_pHash, hinit, 20);
}

void YinyangHashSHA1::ComputeHashFinalHelper(void* msg_digest)
{
	BYTE buf[256];
	DWORD len;
	QWORD string_bit_len;

	memcpy(msg_digest, m_pHash, 20);

	len = m_dwRestLen;
	memcpy(buf, m_pRest, len);
	buf[len++] = 0x80;
	if (len < 56)
		memset(buf + len, 0, 56 - len), len = 56;
	else if (len > 56)
		memset(buf + len, 0, 120 - len), len = 120;
	string_bit_len = m_qwSrcLen * 8;
	ReverseEndian64(buf + len, &string_bit_len, 8);
	len += 8;
	ComputeHashHelper(buf, msg_digest, len);

	ReverseEndian32(msg_digest, msg_digest, 20);
}

DWORD YinyangHashSHA1::ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len)
{
	YinyangHashSHA1Helper(pBuffer, msg_digest, len);
	return len % 64;
}


#define ROUND1(a, b, c, d, e, num) \
    e = ROTATE_L32(a, 5) + ((b&(c^d))^d) + e + w[num] + 0x5a827999; \
    b = ROTATE_R32(b, 2);
#define ROUND2(a, b, c, d, e, num) \
    e = ROTATE_L32(a, 5) + (b^c^d) + e + w[num+20] + 0x6ed9eba1; \
    b = ROTATE_R32(b, 2);
#define ROUND3(a, b, c, d, e, num) \
    e = ROTATE_L32(a, 5) + (((b|c)&d)|(b&c)) + e + w[num+40] + 0x8f1bbcdc; \
    b = ROTATE_R32(b, 2);
#define ROUND4(a, b, c, d, e, num) \
    e = ROTATE_L32(a, 5) + (b^c^d) + e + w[num+60] + 0xca62c1d6; \
    b = ROTATE_R32(b, 2);

#define ROUND(number) \
        ROUND##number(a,b,c,d,e, 0)    ROUND##number(e,a,b,c,d, 1) \
        ROUND##number(d,e,a,b,c, 2)    ROUND##number(c,d,e,a,b, 3) \
        ROUND##number(b,c,d,e,a, 4)    ROUND##number(a,b,c,d,e, 5) \
        ROUND##number(e,a,b,c,d, 6)    ROUND##number(d,e,a,b,c, 7) \
        ROUND##number(c,d,e,a,b, 8)    ROUND##number(b,c,d,e,a, 9) \
        ROUND##number(a,b,c,d,e,10)    ROUND##number(e,a,b,c,d,11) \
        ROUND##number(d,e,a,b,c,12)    ROUND##number(c,d,e,a,b,13) \
        ROUND##number(b,c,d,e,a,14)    ROUND##number(a,b,c,d,e,15) \
        ROUND##number(e,a,b,c,d,16)    ROUND##number(d,e,a,b,c,17) \
        ROUND##number(c,d,e,a,b,18)    ROUND##number(b,c,d,e,a,19)

void YinyangHashSHA1Helper(const void* pBuffer, void* hash, DWORD len)
{
	auto buf = (BYTE*)pBuffer;
	auto h = static_cast<DWORD*>(hash);
	DWORD a, b, c, d, e, t;
	DWORD w[80];
	DWORD i = len / 64;

	a = h[0];
	b = h[1];
	c = h[2];
	d = h[3];
	e = h[4];

	while (i > 0)
	{
		ReverseEndian32(w, buf, 64);

		for (t = 16; t < 80; t++)
			w[t] = ROTATE_L32(w[t-3]^w[t-8]^w[t-14]^w[t-16], 1);

		ROUND(1);
		ROUND(2);
		ROUND(3);
		ROUND(4);

		a += h[0];
		b += h[1];
		c += h[2];
		d += h[3];
		e += h[4];
		h[0] = a;
		h[1] = b;
		h[2] = c;
		h[3] = d;
		h[4] = e;
		buf += 64;
		i--;
	}
}

#include "YinyangHashSHA384.h"


void YinyangHashSHA512Helper(const void* pBuffer, void* hash, DWORD len);

static constexpr QWORD hinit[] = {
	0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
	0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4
};


YinyangHashSHA384::YinyangHashSHA384()
{
	Initialize();
}

YinyangHashSHA384::~YinyangHashSHA384()
{
}


void YinyangHashSHA384::Initialize()
{
	YinyangHashBase::Initialize();
	memcpy(m_pHash, hinit, 64);
}

void YinyangHashSHA384::ComputeHashFinalHelper(void* msg_digest)
{
	BYTE buf[256], hash[64];
	DWORD len;
	QWORD string_bit_len;

	memcpy(hash, m_pHash, 64);

	len = m_dwRestLen;
	memcpy(buf, m_pRest, len);
	buf[len++] = 0x80;
	if (len < 112)
		memset(buf + len, 0, 112 - len), len = 112;
	else if (len > 112)
		memset(buf + len, 0, 240 - len), len = 240;
	string_bit_len = m_qwSrcLen * 8;
	memset(buf + len, 0, sizeof(QWORD));
	ReverseEndian64(buf + len + 8, &string_bit_len, 8);
	len += 16;
	ComputeHashHelper(buf, hash, len);

	ReverseEndian64(msg_digest, hash, 48);
}

DWORD YinyangHashSHA384::ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len)
{
	YinyangHashSHA512Helper(pBuffer, msg_digest, len);
	return len % 128;
}

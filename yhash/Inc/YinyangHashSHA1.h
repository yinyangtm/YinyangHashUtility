#pragma once

#include "YinyangHashBase.h"

class YinyangHashSHA1 : public YinyangHashBase
{
public:
	YinyangHashSHA1();
	~YinyangHashSHA1();

	DWORD GetHashValueSize() override { return 20; }
	DWORD GetHashBlockSize() override { return 64; }
	void Initialize() override;

private:
	DWORD ComputeHashHelper(const void* pBuffer, DWORD len) override
	{
		return ComputeHashHelper(pBuffer, m_pHash, len);
	}

	DWORD ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len) override;
	void ComputeHashFinalHelper(void* msg_digest) override;

private:
	DWORD m_pHash[5];
};

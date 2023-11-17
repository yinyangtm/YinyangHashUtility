#pragma once

#include "YinyangHashBase.h"

class YinyangHashMD5 : public YinyangHashBase
{
public:
	YinyangHashMD5();
	~YinyangHashMD5();

	DWORD GetHashValueSize() override { return 16; }
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
	DWORD m_pHash[4];
};

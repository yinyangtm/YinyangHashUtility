#pragma once

#include "YinyangHashBase.h"

class YinyangHashSHA512 : public YinyangHashBase
{
public:
	YinyangHashSHA512();
	~YinyangHashSHA512();

	DWORD GetHashValueSize() override { return 64; }
	DWORD GetHashBlockSize() override { return 128; }
	void Initialize() override;

private:
	DWORD ComputeHashHelper(const void* pBuffer, DWORD len) override
	{
		return ComputeHashHelper(pBuffer, m_pHash, len);
	}

	DWORD ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len) override;
	void ComputeHashFinalHelper(void* msg_digest) override;

private:
	QWORD m_pHash[8];
};

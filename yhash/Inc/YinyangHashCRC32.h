#pragma once

#include "YinyangHashBase.h"

class YinyangHashCRC32 : public YinyangHashBase
{
public:
	YinyangHashCRC32();
	~YinyangHashCRC32();

	DWORD GetHashValueSize() override { return 4; }
	DWORD GetHashBlockSize() override { return 64; }
	void Initialize() override;

private:
	DWORD ComputeHashHelper(const void* pBuffer, DWORD len) override
	{
		return ComputeHashHelper(pBuffer, &m_dwCRC32, len);
	}

	DWORD ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len) override;
	void ComputeHashFinalHelper(void* msg_digest) override;

private:
	DWORD m_dwCRC32;
};

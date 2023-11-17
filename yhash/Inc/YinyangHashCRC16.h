#pragma once

#include "YinyangHashBase.h"

class YinyangHashCRC16 : public YinyangHashBase
{
public:
	YinyangHashCRC16();
	~YinyangHashCRC16();

	DWORD GetHashValueSize() override { return 2; }
	DWORD GetHashBlockSize() override { return 64; }
	void Initialize() override;

private:
	DWORD ComputeHashHelper(const void* pBuffer, DWORD len) override
	{
		return ComputeHashHelper(pBuffer, nullptr, len);
	}

	DWORD ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len) override;
	void ComputeHashFinalHelper(void* msg_digest) override;

private:
	DWORD m_dwCRC16;
};

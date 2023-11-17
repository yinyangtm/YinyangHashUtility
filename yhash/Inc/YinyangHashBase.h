#pragma once

#include "YinyangHashHeader.h"

class YinyangHashBase
{
public:
	YinyangHashBase();
	~YinyangHashBase();

	virtual DWORD GetHashValueSize() =0;
	virtual DWORD GetHashBlockSize() =0;
	virtual void Initialize();
	void ComputeHash(const void* pBuffer, DWORD len);

	void GetHashValue(void* msg_digest);
	void GetHashValueWithoutInitializing(void* msg_digest);
	void GetHashString(char* pStrBuf, BOOL bSmallString);

	int CmpHashValue(const char* pHashStr);

protected:
	virtual DWORD ComputeHashHelper(const void* pBuffer, DWORD len) =0;
	virtual DWORD ComputeHashHelper(const void* pBuffer, void* msg_digest, DWORD len) =0;
	virtual void ComputeHashFinalHelper(void* msg_digest) =0;

protected:
	DWORD m_dwRestLen;
	QWORD m_qwSrcLen;
	BYTE m_pRest[512];
};

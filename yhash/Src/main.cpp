#include <stdio.h>
#include <string.h>

#include "YinyangHashMD5.h"
#include "YinyangHashCRC16.h"
#include "YinyangHashCRC32.h"
#include "YinyangHashSHA1.h"
#include "YinyangHashSHA256.h"
#include "YinyangHashSHA384.h"
#include "YinyangHashSHA512.h"

constexpr auto HASH_BUFFER_SIZE = 256;
constexpr auto FILE_READ_BUFFER_SIZE = 32768;


enum algorithm
{
	MD5,
	CRC16,
	CRC32,
	SHA1,
	SHA256,
	SHA384,
	SHA512
};

void PrintHelp();
void GetHash(char* hash, char* file, algorithm algorithm);

int main(int argc, char* argv[])
{
	char hash[HASH_BUFFER_SIZE];
	algorithm al = SHA256;

	// help
	if (argc == 2 && strcmp(argv[1], "-h") == 0)
	{
		PrintHelp();
		return 0;
	}

	// Flag
	switch (argc)
	{
	case 2:
		if (strcmp(argv[1], "-h") == 0)
		{
			PrintHelp();
		}
		else
		{
			GetHash(hash, argv[1], al);
			printf("%s\n", hash);
		}
		break;
	case 4:
		if (strcmp(argv[1], "-m") == 0)
		{
			if (strcmp(argv[2], "crc16") == 0)
			{
				al = CRC16;
			}
			else if (strcmp(argv[2], "crc32") == 0)
			{
				al = CRC32;
			}
			else if (strcmp(argv[2], "md5") == 0)
			{
				al = MD5;
			}
			else if (strcmp(argv[2], "sha1") == 0)
			{
				al = SHA1;
			}
			else if (strcmp(argv[2], "sha256") == 0)
			{
				al = SHA256;
			}
			else if (strcmp(argv[2], "sha384") == 0)
			{
				al = SHA384;
			}
			else if (strcmp(argv[2], "sha512") == 0)
			{
				al = SHA512;
			}
			else
			{
				printf("The algorithm specification is incorrect.\n");
				return 0;
			}
			GetHash(hash, argv[3], al);
			printf("%s\n", hash);
		}
		else if (strcmp(argv[1], "-c") == 0)
		{
			char hash2[HASH_BUFFER_SIZE];
			GetHash(hash, argv[2], al);
			GetHash(hash2, argv[3], al);
			printf("File 1: %s\n", hash);
			printf("File 2: %s\n", hash2);
			if (strcmp(hash, hash2) == 0)
			{
				printf("File: Match!\n");
			}
			else
			{
				printf("File: Mismatch...\n");
			}
		}
		else if (strcmp(argv[1], "-i") == 0)
		{
			GetHash(hash, argv[2], al);
			printf("File 1: %s\n", hash);
			printf("Input : %s\n", argv[3]);
			if (strcmp(hash, argv[3]) == 0)
			{
				printf("File: Match!\n");
			}
			else
			{
				printf("File: Mismatch...\n");
			}
		}
		else
		{
			PrintHelp();
		}
		break;
	default:
		PrintHelp();
		return 0;
	}

	return 0;
}

void GetHash(char* hash, char* file, algorithm algorithm)
{
	FILE* pFile;
	errno_t err;
	size_t size;
	char fileReadBuffer[FILE_READ_BUFFER_SIZE];

	err = fopen_s(&pFile, file, "rb");
	if (err != 0)
	{
		printf("Unable to open the file.\n");
		strcpy_s(hash, HASH_BUFFER_SIZE, "Error: File open failed");
		return;
	}

	try
	{
		size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
		if (algorithm == MD5)
		{
			YinyangHashMD5 md5;
			while (size > 0)
			{
				md5.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			md5.GetHashString(hash, TRUE);
		}
		else if (algorithm == CRC16)
		{
			YinyangHashCRC16 crc16;
			while (size > 0)
			{
				crc16.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			crc16.GetHashString(hash, TRUE);
		}
		else if (algorithm == CRC32)
		{
			YinyangHashCRC32 crc32;
			while (size > 0)
			{
				crc32.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			crc32.GetHashString(hash, TRUE);
		}
		else if (algorithm == SHA1)
		{
			YinyangHashSHA1 sha1;
			while (size > 0)
			{
				sha1.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			sha1.GetHashString(hash, TRUE);
		}
		else if (algorithm == SHA256)
		{
			YinyangHashSHA256 sha256;
			while (size > 0)
			{
				sha256.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			sha256.GetHashString(hash, TRUE);
		}
		else if (algorithm == SHA384)
		{
			YinyangHashSHA384 sha384;
			while (size > 0)
			{
				sha384.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			sha384.GetHashString(hash, TRUE);
		}
		else if (algorithm == SHA512)
		{
			YinyangHashSHA512 sha512;
			while (size > 0)
			{
				sha512.ComputeHash(fileReadBuffer, size);
				size = fread(fileReadBuffer, 1, FILE_READ_BUFFER_SIZE, pFile);
			}
			sha512.GetHashString(hash, TRUE);
		}
	}
	catch (...)
	{
		printf("Error GetHash.\n");
		strcpy_s(hash, HASH_BUFFER_SIZE, "Error GetHash");
	}
	if (fclose(pFile))
	{
		printf("Unable to open the file.\n");
		strcpy_s(hash, HASH_BUFFER_SIZE, "Error GetHash-fclose");
	}
}

void PrintHelp()
{
	printf("Yinyang Hash Utility Usage:\n");
	printf("  [Usage] yhash <option> <file> [algorithm] [comparison string]\n\n");
	printf("Options:\n");
	printf(
		"  -m <algorithm> <file>: Specify the algorithm to use for hashing the file. Available algorithms are crc16, crc32, md5, sha1, sha256, sha384, sha512.\n");
	printf("  -c <file1> <file2>: Compare the hash of two files using the SHA256 algorithm.\n");
	printf(
		"  -i <file> <string>: Compare the hash of a file with the provided hash string using the SHA256 algorithm.\n");
	printf("  -h: Display this help message.\n\n");
	printf("Examples:\n");
	printf("  yhash -m md5 myfile.txt: Compute the MD5 hash of 'myfile.txt'.\n");
	printf("  yhash -c file1.txt file2.txt: Compare the SHA256 hashes of 'file1.txt' and 'file2.txt'.\n");
	printf(
		"  yhash -i myfile.txt 123456789abcdef: Compare the SHA256 hash of 'myfile.txt' with the provided hash string.\n");
}

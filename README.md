# Yinyang Hash Utility



## Overview - 概要

The Yinyang Hash Utility is a tool designed to compute hash values of files using various hash algorithms.

It supports a range of algorithms, including MD5, CRC16, CRC32, SHA1, SHA256, SHA384, and SHA512.

Yinyang Hash Utilityは、さまざまなハッシュアルゴリズムを使用してファイルのハッシュ値を計算を行うツールです。

サポートされているハッシュアルゴリズムには、MD5、CRC16、CRC32、SHA1、SHA256、SHA384、SHA512が含まれます。

---

## yhash

This is a command-line tool for Windows that allows for the comparison of hash values either between files or between a file and a specified hash string.

ファイル間またはファイルと指定されたハッシュ文字列との比較を行うWindows用コマンドラインツールです。

```
Yinyang Hash Utility Usage:
  [Usage] yhash <option> <file> [algorithm] [comparison string]

Options:
  -m <algorithm> <file>: Specify the algorithm to use for hashing the file. Available algorithms are crc16, crc32, md5, sha1, sha256, sha384, sha512.
  -c <file1> <file2>: Compare the hash of two files using the SHA256 algorithm.
  -i <file> <string>: Compare the hash of a file with the provided hash string using the SHA256 algorithm.
  -h: Display this help message.

Examples:
  yhash -m md5 myfile.txt: Compute the MD5 hash of 'myfile.txt'.
  yhash -c file1.txt file2.txt: Compare the SHA256 hashes of 'file1.txt' and 'file2.txt'.
  yhash -i myfile.txt 123456789abcdef: Compare the SHA256 hash of 'myfile.txt' with the provided hash string.
```



```
Yinyang Hash Utility Usage:
  [Usage] yhash <オプション> <ファイル> [アルゴリズム] [ハッシュ]

オプション:
  -m <アルゴリズム> <ファイル>: ファイルを指定されたアルゴリズムでハッシュを計算します。
  対応しているアルゴリズムは crc16, crc32, md5, sha1, sha256, sha384, sha512 です。
  
  -c <ファイル1> <ファイル2>: ファイル1とファイル2を SHA256 で比較します。
  
  -i <ファイル> <SHA256ハッシュ値>: ファイルが入力されたSHA256ハッシュ値を一致するか比較します。
  
  -h: ヘルプを表示します。

例:
  yhash -m md5 myfile.txt　: MD5で'myfile.txt'のハッシュ値を計算します。
  yhash -c file1.txt file2.txt　: 'file1.txt' と 'file2.txt' を比較します。
  yhash -i myfile.txt 123456789abcdef　: 'myfile.txt' のハッシュ値と入力されたハッシュ値を比較します。
```



---


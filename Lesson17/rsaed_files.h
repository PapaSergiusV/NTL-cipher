#ifndef RSAED_FILES_H
#define RSAED_FILES_H

#include <cstdio>
#include <fstream>
#include <string>
#include <type_traits>
#include "rsa_keys.h"

using namespace std;

class rsaed_ofile
{
	FILE * file;
	PubKey key;
	unsigned char * buf;
	int buf_size;
	int buf_size_plain;
	int buf_occupied;

public:
	rsaed_ofile(string path, string pathKey) 
	{
		file = fopen(path.c_str(), "wb");
		ifstream ifstr(pathKey.c_str());
		ifstr >> key.e;
		ifstr >> key.n;
		buf_size = NTL::NumBytes(key.n);
		buf_size_plain = buf_size - 1;
		buf = new unsigned char[buf_size];
		buf_occupied = 0;
	}

	~rsaed_ofile()
	{
		if (buf_occupied > 0)
			flush_buffer();
		fclose(file);
		delete[] buf;
	}

	//запрет конструктора копии
	rsaed_ofile(const rsaed_ofile & ro) = delete;

	rsaed_ofile & operator=(const rsaed_ofile & ro) = delete;

	// запись в шифрованный файл
	template <typename T>
	rsaed_ofile & operator<<(T const & t)
	{
		static_assert(is_pod<T>::value && !is_pointer<T>::value); // C/C++ --> Все параметры --> Дополнительные параметры --> /wd4146 /std:c++17
		T * p = const_cast<T*>(&t);
		n_bytes_to_buffer(static_cast<void*>(p), sizeof(T));
		return *this;
	}

private:

	// поместить в буффер n байт из памяти по адресу p
	void n_bytes_to_buffer(void * p, int n)
	{
		auto q = static_cast<unsigned char *>(p);
		for (int i = 0; i < n; ++i)                 // побайтовая запись с контролем границы буфера
		{
			if (buf_occupied == buf_size_plain)
				flush_buffer();
			buf[buf_occupied++] = *q++;
		}
	}

	// сброс содержимого буфера в файл с предварительным шифрованием
	void flush_buffer()
	{
		ZZ m = NTL::ZZFromBytes(buf, buf_occupied);  // buf_occupied -- количество байт исходных данных
		ZZ mrca = PowerMod(m, key.e, key.n); // шифрограмма
		NTL::BytesFromZZ(buf, mrca, buf_size);       // размер шифрограммы — buf_size
		fwrite(buf, sizeof(char), buf_size, file);
		buf_occupied = 0;
	}
};

class rsaed_ifile
{
	FILE * file;
	PrivateKey key;
	unsigned char * buf;
	int buf_size;
	int buf_size_plain;
	int buf_consumed;

public:
	rsaed_ifile(string path, string pathKey)
	{
		file = fopen(path.c_str(), "rb");
		ifstream ifstr(pathKey.c_str());
		ifstr >> key.d;
		ifstr >> key.n;
		buf_size = NTL::NumBytes(key.n);
		buf_size_plain = buf_size - 1;
		buf = new unsigned char[buf_size];
		buf_consumed = buf_size_plain;
	}

	~rsaed_ifile()
	{
		fclose(file);
		delete[] buf;
	}

	//запрет конструктора копии
	rsaed_ifile(const rsaed_ifile & ri) = delete;

	rsaed_ifile & operator=(const rsaed_ifile & ri) = delete;

	// чтение целого значения из зашифрованного файла
	template <typename T>
	rsaed_ifile & operator>>(T & m)
	{
		static_assert(is_pod<T>::value && !is_pointer<T>::value); // C/C++ --> Все параметры --> Дополнительные параметры --> /wd4146 /std:c++17
		n_bytes_from_buffer(&m, sizeof(T));
		return *this;
	}

private:

	void n_bytes_from_buffer(void * p, int n)
	{
		auto q = static_cast<unsigned char *>(p);
		for (int i = 0; i < n; ++i)
		{
			if (buf_consumed == buf_size_plain)
				load_buffer();
			*q++ = buf[buf_consumed++];
		}
	}

	void load_buffer()
	{
		fread(buf, sizeof(unsigned char), buf_size, file);
		ZZ zNum = NTL::ZZFromBytes(buf, buf_size);
		ZZ res = NTL::PowerMod(zNum, key.d, key.n);
		NTL::BytesFromZZ(buf, res, buf_consumed);
		buf_consumed = 0;
	}
};

#endif // !RSAED_FILES_H

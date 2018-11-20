#include <iostream>
#include <cstdio>
#include <string>
#include <cassert>
#include "rsaed_files.h"
#include "rsa_keys.h"

using namespace std;

int main()
{
	setlocale(LC_ALL, "Russian");

	// ���� � ������ �������
	{
		rsaed_ofile ofile("my_file", "id_rsa.pub");
		ofile << 42;
		ofile << -5;
	}

	{
		rsaed_ifile ifile("my_file", "id_rsa");
		int res;
		ifile >> res;
		assert(res == 42);
		ifile >> res;
		assert(res == -5);
	}
	cout << "������ � ������ int - ����� ��������." << endl;


	// ���� � ������� double
	{
		rsaed_ofile ofile("my_file", "id_rsa.pub");
		ofile << 9.5;
		ofile << 4.32;
	}

	{
		rsaed_ifile ifile("my_file", "id_rsa");
		double res_d;
		ifile >> res_d;
		assert(fabs(9.5 - res_d) < DBL_EPSILON);
		ifile >> res_d;
		assert(fabs(4.32 - res_d) < DBL_EPSILON);
	}
	cout << "������ � ������ double - ����� ��������." << endl;


	system("pause");
}

//������ � ������ int - ����� ��������.
//������ � ������ double - ����� ��������.
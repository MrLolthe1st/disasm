#include <iostream>
#include "disasm.h"
using namespace std;
int main()
{
	std::string s = disasm_code("ac", MODE_16);
	cout << s;
	build_structure(s);
	int a;
	cin >> a;
	return 0;
}
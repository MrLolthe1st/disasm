#include <iostream>
#include "disasm.h"
using namespace std;
int main()
{
	cout<<disasm_code("ac", MODE_16);
	int a;
	cin >> a;
	return 0;
}
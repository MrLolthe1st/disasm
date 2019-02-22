#include <iostream>
#include "disasm.h"
using namespace std;
int main()
{
	cout<<disasm_code("asm\\ac", MODE_32);
	int a;
	cin >> a;
	return 0;
}
/*
	disasm.cpp - disassembler and other structures. Converts bytes to assembler code.
	Simply logic recovery to pseudo C-like style. Main convertion to code, that will
	be analyzed later will be in clogic.cpp.
	Copyright (C) 2019  Novozhilov Alexandr (MrLolthe1st)
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string>
#include <fstream>
#include "disasm.h"


//There are main register table, sorted in intel-asm style (000 is ax, 001 is cx and e.g.)
std::vector<std::string> reg_names = {
	"ah", "al", "ax", "eax", "rax",
	"ch", "cl", "cx", "ecx", "rcx",
	"dh", "dl", "dx", "edx", "rdx",
	"bh", "bl", "bx", "ebx", "rbx",
	"--", "--", "sp", "esp", "rsp",
	"--", "--", "bp", "ebp", "rbp",
	"--", "--", "si", "esi", "rsi",
	"--", "--", "di", "edi", "rdi",
	"es", "cs", "ss", "ds", "fs", "gs"
};

//8-bit registers is excepted
std::vector<std::string> reg8_names = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
};

void disasm_init()
{

}

void init_transitions()
{

}

//Returns a segment register, ds will be replaced with 0x7F character(del).
std::string SREG_GET(int f, bool a = false)
{
	if (f == 3 && !a)
		return std::string(1, 0x7f);
	//We're return by mod, because sometimes it greater, that table size
	return  (reg_names[((f)+SREG_OFFSET) % reg_names.size()]);
}

//Checks if char C is string-char
bool is_string(char c)
{
	return (c == ' ' || c == '\n' || c == '\t' || c == '\b' || (c >= 'a'&&c <= 'z') || (c >= 'A'&&c <= 'Z'));
}

std::vector<std::string> bytes_names_by_op_size = { "-", "b", "w", "d" };

std::vector<int> addr_overrides = { 32, 16, 32 };

std::vector<int> addr_overrides_1 = { 32, 16, 64 };

//Computes a logarithm of power of two
int log2c(int a)
{
	int cnt = 0;
	while (a > 1)
	{
		cnt++;
		a /= 2;
	}
	return cnt;
}

//Converts U 8-byte to Signed BTS-byte number
long long conv(unsigned long long a, int bts)
{
	if (bts == 1)
		return (char)a;
	else if (bts == 2)
		return (short)a;
	else if (bts == 4)
		return (int)a;
	else return (long long)a;
}

//Returns string of char x
std::string get_string(char x)
{
	// string class has a constructor 
	// that allows us to specify size of 
	// string as first parameter and character 
	// to be filled in given size as second 
	// parameter. 
	if (x == '\n')
		return "\\n";
	if (x == '\b')
		return "\\b";
	if (x == '\t')
		return "\\t";
	std::string s(1, x);

	return s;
}

//O(1) access to dword, qword, and etc.
std::vector<std::string> bytes_names(65);

//O(1) convertation byte to hex-representation
std::string table("0123456789ABCDEF");

std::string get_hex(unsigned char c)
{
	std::string a;
	a.push_back(table[(int)c >> 4]);
	a.push_back(table[(int)c & 15]);
	return  a;
}

//Returns intel-style register name
std::string get_reg(int op_size, int ndx)
{
	if (op_size == 8)
		return reg8_names[ndx];
	else return REG_GET(op_size, ndx);
}

//Crutch: mov [es:bp + 3], ...
std::vector<int> map_tab = { 0, 0, 0, 0, 6, 7, 5, 3 };

std::string get_reg1(int op_size, int ndx)
{
	if (op_size == 8)
		return reg8_names[ndx];
	else {
		//Crutch: mov [bp + si], ...
		if (ndx == 0)
			return "bx+si";
		if (ndx == 1)
			return "bx+di";
		if (ndx == 2)
			return "bp+si";
		if (ndx == 3)
			return "bp+di";
		return REG_GET(op_size, map_tab[ndx]);
	}
}

//Parses representation of operands, provided next byte in ifstream.
//Gets opcode, and masks it with mask.
//There are 3 situations:
//reg, reg		ax, bx
//reg, mem		ax, [0xDEAD]
//reg, reg_mem	ax, [bp + si]
std::string parse_ops(int mode, int seg_reg, int op_size, int addr_size, std::ifstream &fl, int cnt, int dir, int mask, bool use = false, bool use_sizes = true, int o_s = 0)
{
	std::string res = ""; unsigned char op_code = 0;
	//Read an opcode desc and regs
	fl.read((char*)&op_code, 1);
	op_code &= mask;
	std::string regs[2];	regs[0] = get_reg(op_size, op_code & 0b111);
	regs[1] = get_reg(op_size, (op_code & 0b111000) >> 3);
	if ((op_code & 0b11000000) == 0b11000000)
	{
		int strt = cnt - 1;	if (dir == 1)	strt = 0;
		for (int i = strt; i > -1 && i < cnt; i += dir)
			res += regs[i] + ", ";
		res = res.substr(0, res.length() - 2);
	}
	else {
		int off_cnt = (op_code & 0b11000000) >> 6, offset = 0;

		if ((op_code & 0b111) != 0x06 - mode || addr_size != (1 << (mode + 4)) || off_cnt > 0) {
			//[es:si]
			std::string op1 = "";
			if (use_sizes)op1 += bytes_names[op_size];
			else op1 += bytes_names[o_s / 2];
			op1 += " [" + SREG_GET(seg_reg) + ":";
			if (addr_size == 16) op1 += get_reg1(addr_size, op_code & 0b111);
			else {
				op1 += get_reg(addr_size, op_code & 0b111);
				if ((op_code & 0b111) == 4) fl.seekg(1, fl.cur);
			}
			if (off_cnt > 0)	fl.read((char*)&offset, off_cnt);
			if (conv(offset, off_cnt) > 0)		op1 += "+";
			if (offset != 0)	op1 += std::to_string(conv(offset, off_cnt));
			op1 += "]";
			if (cnt > 1) {
				if (dir == 1)	res += op1 + ", " + regs[1];
				else res += regs[1] + ", " + op1;
			}
			else { res += op1; }
		}
		else //[es:addr]
		{
			unsigned long long addr = 0;
			fl.read((char*)&addr, (1 << (mode + 4)) / 8);
			std::string op1 = "";
			if (use_sizes)op1 += bytes_names[op_size];
			else op1 += bytes_names[o_s / 2];
			op1 += " [" + SREG_GET(seg_reg) + ":" + std::to_string(addr) + "]";
			if (cnt > 1) {
				if (dir == 1)	res += op1 + ", " + regs[1];
				else res += regs[1] + ", " + op1;
			}
			else res += op1;
		}
	}
	if (use)
		return res;
	return res + "\n";
}

//Disassembles the code
std::string disasm_code(std::string filename, int mode)
{
	bytes_names[8] = "byte";
	bytes_names[16] = "word";
	bytes_names[32] = "dword";
	bytes_names[64] = "qword";
	std::string result = "; That code was generated by MrLolthe1st disassembler v0.0.1\n";
	std::ifstream fl(filename, std::ios::binary);
	if (!fl.is_open()) {

		return "1";
	}
	unsigned char * buffer = (unsigned char*)malloc(8);
	int seg_reg = 3, op_size = 1 << (mode + 4), addr_size = 1 << (mode + 4);
	unsigned char last_byte = 0; std::string rep_pr = "";
	long long cur = fl.tellg();
	bool read = true;
	while (1) {
		last_byte = *buffer; int lb = 0;
		unsigned long long a = 0;
		if (!read) {
			cur = fl.tellg();
			read = true;
		}
		fl.read((char*)buffer, 1);

		if (fl.eof())
			break;
		if (*buffer >= 0x91 && *buffer < 0x98)
		{
			result += "xchg eax, ";
			result += get_reg(op_size, *buffer - 0x90) + "\n";
			goto ennnnd;
		}
		if (*buffer >= 0x40 && *buffer <= 0x4F)
		{
			if (!(*buffer & 0x8))result += "inc ";
			else result += "dec ";
			result += get_reg(op_size, *buffer&(~8) - 0x40) + "\n";
			goto ennnnd;
		}
		if (*buffer >= 0x50 && *buffer <= 0x5F)
		{
			if (!(*buffer & 0x8))result += "push ";
			else result += "pop ";
			result += get_reg(op_size, *buffer&(~8) - 0x50) + "\n";
			goto ennnnd;
		}
		if (*buffer >= 0xB0 && *buffer <= 0xBF)
		{
			if (!(*buffer & 0x8)) { op_size = 8; };
			fl.read((char*)&a, op_size / 8);
			result += "mov " + get_reg(op_size, *buffer&(~8) - 0xB0) + ", " + std::to_string(a) + "\n";
			goto ennnnd;
		}
		switch (*buffer)
		{
		case 0x0:
			result += "add " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1:
			result += "add " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2:
			result += "add " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3:
			result += "add " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4:
			fl.read((char*)&a, 1);
			result += "add al, " + std::to_string(a) + "\n";
			break;
		case 0x5:
			fl.read((char*)&a, op_size / 8);
			result += "add " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x6:
			result += "push es\n";
			break;
		case 0x7:
			result += "pop es\n";
			break;
		case 0x0 + 0x008:
			result += "or " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x008:
			result += "or " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x008:
			result += "or " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x008:
			result += "or " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x008:
			fl.read((char*)&a, 1);
			result += "or al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x008:
			fl.read((char*)&a, op_size / 8);
			result += "or " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0xE:
			result += "push cs\n";
			break;
		case 0x0 + 0x010:
			result += "adc " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x010:
			result += "adc " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x010:
			result += "adc " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x010:
			result += "adc " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x010:
			fl.read((char*)&a, 1);
			result += "adc al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x010:
			fl.read((char*)&a, op_size / 8);
			result += "adc " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x16:
			result += "push ss\n";
			break;
		case 0x17:
			result += "pop ss\n";
			break;
		case 0x0 + 0x018:
			result += "sbb " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x018:
			result += "sbb " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x018:
			result += "sbb " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x018:
			result += "sbb " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x018:
			fl.read((char*)&a, 1);
			result += "sbb al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x018:
			fl.read((char*)&a, op_size / 8);
			result += "sbb " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x1E:
			result += "push ds\n";
			break;
		case 0x1F:
			result += "pop ds\n";
			break;
		case 0x0 + 0x020:
			result += "and " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x020:
			result += "and " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x020:
			result += "and " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x020:
			result += "and " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x020:
			fl.read((char*)&a, 1);
			result += "and al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x020:
			fl.read((char*)&a, op_size / 8);
			result += "and " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x26: // ES Override
			seg_reg = 0;
			result += ";ES Override\n";
			continue;
		case 0x0 + 0x028:
			result += "sub " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x028:
			result += "sub " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x028:
			result += "sub " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x028:
			result += "sub " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x028:
			fl.read((char*)&a, 1);
			result += "sub al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x028:
			fl.read((char*)&a, op_size / 8);
			result += "sub " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x2E: // CS Override
			seg_reg = 1;
			result += ";CS Override\n";
			continue;
		case 0x0 + 0x030:
			result += "xor " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x030:
			result += "xor " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x030:
			result += "xor " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x030:
			result += "xor " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x030:
			fl.read((char*)&a, 1);
			result += "xor al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x030:
			fl.read((char*)&a, op_size / 8);
			result += "xor " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x36: // SS Override
			seg_reg = 2;
			result += ";SS Override\n";
			continue;
		case 0x0 + 0x038:
			result += "cmp " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x1 + 0x038:
			result += "cmp " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x2 + 0x038:
			result += "cmp " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x3 + 0x038:
			result += "cmp " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x4 + 0x038:
			fl.read((char*)&a, 1);
			result += "cmp al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x038:
			fl.read((char*)&a, op_size / 8);
			result += "cmp " + get_reg(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x3E: // DS Override
			seg_reg = 3;
			result += ";DS Override\n";
			continue;
		case 0x48:
			op_size = 64;
			result += ";Opcode size override 64\n";
			continue;
		case 0x60:
			if (op_size == 32)
				result += "pushad\n";
			else
				result += "pusha\n";
			break;
		case 0x61:
			if (op_size == 32)
				result += "popad\n";
			else
				result += "popa\n";
			break;
		case 0x64: // FS Override
			seg_reg = 4;
			result += ";FS Override\n";
			break;
		case 0x65: // GS Override
			seg_reg = 5;
			result += ";GS Override\n";
			break;
		case 0x66:
			op_size = addr_overrides[mode];
			result += ";Opcode size override\n";
			continue;
		case 0x67:
			addr_size = addr_overrides[mode];
			result += ";Address size override\n";
			continue;
		case 0x68:
			fl.read((char*)&a, op_size / 8);
			result += "push " + bytes_names[op_size] + " " + std::to_string(a) + "\n";
			break;
		case 0x6A:
			fl.read((char*)&a, 1);
			result += "push byte " + std::to_string(a) + "\n";
			break;

		case 0x6C:
			result += rep_pr + "insb\n";
			rep_pr = "";
			break;
		case 0x6D:
			result += rep_pr + "ins" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0x6E:
			result += rep_pr + "outsb\n";
			rep_pr = "";
			break;
		case 0x6F:
			result += rep_pr + "outs" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0x70:
			fl.read((char*)&a, 1);
			result += "jo short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x71:
			fl.read((char*)&a, 1);
			result += "jno short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x72:
			fl.read((char*)&a, 1);
			result += "jc short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x73:
			fl.read((char*)&a, 1);
			result += "jnc short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x74:
			fl.read((char*)&a, 1);
			result += "jz short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x75:
			fl.read((char*)&a, 1);
			result += "jnz short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x76:
			fl.read((char*)&a, 1);
			result += "jna short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x77:
			fl.read((char*)&a, 1);
			result += "ja short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x78:
			fl.read((char*)&a, 1);
			result += "js short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x79:
			fl.read((char*)&a, 1);
			result += "jns short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7A:
			fl.read((char*)&a, 1);
			result += "jpe short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7B:
			fl.read((char*)&a, 1);
			result += "jpo short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7C:
			fl.read((char*)&a, 1);
			result += "jl short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7D:
			fl.read((char*)&a, 1);
			result += "jnl short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7E:
			fl.read((char*)&a, 1);
			result += "jng short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x7F:
			fl.read((char*)&a, 1);
			result += "jg short ";
			if (conv(a, 1) > 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0x80:
			op_size = 8;
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "add ";
				break;
			case 1:
				result += "or ";
				break;
			case 2:
				result += "adc ";
				break;
			case 3:
				result += "sbb ";
				break;
			case 4:
				result += "and ";
				break;
			case 5:
				result += "sub ";
				break;
			case 6:
				result += "xor ";
				break;
			case 7:
				result += "cmp ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, 1);
			result += std::to_string(a) + "\n";
			break;
		case 0x81:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "add ";
				break;
			case 1:
				result += "or ";
				break;
			case 2:
				result += "adc ";
				break;
			case 3:
				result += "sbb ";
				break;
			case 4:
				result += "and ";
				break;
			case 5:
				result += "sub ";
				break;
			case 6:
				result += "xor ";
				break;
			case 7:
				result += "cmp ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, op_size / 8);
			result += std::to_string(a) + "\n";
			break;
		case 0x82:
			op_size = 8;
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "add ";
				break;
			case 1:
				result += "or ";
				break;
			case 2:
				result += "adc ";
				break;
			case 3:
				result += "sbb ";
				break;
			case 4:
				result += "and ";
				break;
			case 5:
				result += "sub ";
				break;
			case 6:
				result += "xor ";
				break;
			case 7:
				result += "cmp ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, 1);
			result += std::to_string(a) + "\n";
			break;
		case 0x83:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "add ";
				break;
			case 1:
				result += "or ";
				break;
			case 2:
				result += "adc ";
				break;
			case 3:
				result += "sbb ";
				break;
			case 4:
				result += "and ";
				break;
			case 5:
				result += "sub ";
				break;
			case 6:
				result += "xor ";
				break;
			case 7:
				result += "cmp ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, 1);
			result += std::to_string(a) + "\n";
			break;
		case 0x84:
			result += "test " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x85:
			result += "test " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x86:
			result += "xchg " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x87:
			result += "xchg " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x88:
			result += "mov " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x89:
			result += "mov " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, 1, 0xFF);
			break;
		case 0x8A:
			result += "mov " + parse_ops(mode, seg_reg, 8, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x8B:
			result += "mov " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF);
			break;
		case 0x8C:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			result += "mov " + parse_ops(mode, seg_reg, 16, addr_size, fl, 1, 1, 0xFF, 1) + ", " + SREG_GET((a & 0b111000) >> 3, true) + "\n";
			break;
		case 0x8D:
			result += "lea " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF, false, false, 0);
			break;
		case 0x8E:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			result += "mov " + SREG_GET((a & 0b111000) >> 3, true) + ", " + parse_ops(mode, seg_reg, 16, addr_size, fl, 1, 1, 0xFF);
			break;
		case 0x8F:
			result += "pop " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0xFF);
			break;
		case 0x90:
			result += "nop\n";
			break;
		case 0x98:
			if (op_size == 16)
				result += "cbw\n";
			else if (op_size == 32) result += "cwde\n";
			else if (op_size == 64) result += "cdqe\n";
			break;
		case 0x99:
			if (op_size == 16)
				result += "cwd\n";
			else if (op_size == 32) result += "cdq\n";
			else if (op_size == 64) result += "cqo\n";
			break;
		case 0x9B:
			result += "wait\n";
			break;
		case 0x9C:
			result += "pushf\n";
			break;
		case 0x9D:
			result += "popf\n";
			break;
		case 0x9E:
			result += "sahf\n";
			break;
		case 0x9F:
			result += "lahf\n";
			break;

		case 0xA0:
			fl.read((char*)&a, op_size / 8);
			result += "mov al, [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			break;
		case 0xA1:
			fl.read((char*)&a, op_size / 8);
			result += "mov " + get_reg(op_size, 0) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			break;
		case 0xA2:
			fl.read((char*)&a, op_size / 8);
			result += "mov [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], al\n";
			break;
		case 0xA3:
			fl.read((char*)&a, op_size / 8);
			result += "mov [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + get_reg(op_size, 0) + "\n";
			break;
		case 0xA4:
			result += rep_pr + "movsb\n";
			break;
		case 0xA5:
			result += rep_pr + "movs" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0xA6:
			result += rep_pr + "cmpsb\n";
			rep_pr = "";
			break;
		case 0xA7:
			result += rep_pr + "cmps" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0xA8:
			fl.read((char*)&a, op_size / 8);
			result += "test al, [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			break;
		case 0xA9:
			fl.read((char*)&a, op_size / 8);
			result += "test " + get_reg(op_size, 0) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			break;
		case 0xAA:
			result += rep_pr + "stosb\n";
			rep_pr = "";
			break;
		case 0xAB:
			result += rep_pr + "stos" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0xAC:
			result += rep_pr + "lodsb\n";
			rep_pr = "";
			break;
		case 0xAD:
			result += rep_pr + "lods" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0xAE:
			result += rep_pr + "scasb\n";
			rep_pr = "";
			break;
		case 0xAF:
			result += rep_pr + "scas" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
			rep_pr = "";
			break;
		case 0xC0:
			op_size = 8;
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, 1);
			result += std::to_string(a) + "\n";
			break;
		case 0xC1:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 0;
			fl.read((char*)&a, 1);
			result += std::to_string(a) + "\n";
			break;
		case 0xC2:
			result += "retn\n";
			break;
		case 0xC3:
			result += "ret\n";
			break;
		case 0xCB:
			result += "retf\n";
			break;
		case 0xCC:
			result += "int 3\n";
			break;
		case 0xCD:
			fl.read((char*)buffer, 1);
			result += "int " + std::to_string(*buffer) + "\n";
			break;
		case 0xCF:
			if (op_size == 64)
				result += "iretq\n";
			else if (op_size == 32)
				result += "iretd\n";
			else if (op_size == 16)
				result += "iretb\n";
			break;
		case 0xD0:
			op_size = 8;
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 1;
			result += std::to_string(a) + "\n";
			break;
		case 0xD1:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			a = 1;
			result += std::to_string(a) + "\n";
			break;
		case 0xD2:
			op_size = 8;
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			result += "cl\n";
			break;
		case 0xD3:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "rol ";
				break;
			case 1:
				result += "ror ";
				break;
			case 2:
				result += "rcl ";
				break;
			case 3:
				result += "rcr ";
				break;
			case 4:
				result += "shl ";
				break;
			case 5:
				result += "shr ";
				break;
			case 6:
				result += "shl ";
				break;
			case 7:
				result += "sar ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, true) + ", ";
			result += "cl\n";
			break;

		case 0xE0:
			fl.read((char*)&a, 1);
			result += "loopnz near ";
			if (conv(a, 1) >= 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0xE1:
			fl.read((char*)&a, 1);
			result += "loopz near ";
			if (conv(a, 1) >= 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0xE2:
			fl.read((char*)&a, 1);
			result += "loop near ";
			if (conv(a, 1) >= 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0xE3:
			fl.read((char*)&a, 1);
			result += "JECXZ near ";
			if (conv(a, 1) >= 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0xE4:
			fl.read((char*)&a, 1);
			result += "in al, " + std::to_string(a) + "\n";
			break;
		case 0xE5:
			fl.read((char*)&a, 1);
			result += "in " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0xE6:
			fl.read((char*)&a, 1);
			result += "out " + std::to_string(a) + ", al\n";
			break;
		case 0xE7:
			fl.read((char*)&a, 1);
			result += "out " + std::to_string(a) + ", " + REG_GET(op_size, 0) + "\n";
			break;
		case 0xE8:
			fl.read((char*)&a, mode * 2 + 2);
			result += "call ";
			if (conv(a + cur + mode * 2 + 3, mode * 2 + 2) >= 0) result += "+";
			result += std::to_string(conv(a + cur + mode * 2 + 3, mode * 2 + 2)) + "\n";
			break;
		case 0xE9:
			fl.read((char*)&a, mode * 2 + 2);
			result += "jmp ";
			if (conv(a, mode * 2 + 2) >= 0) result += "+";
			result += std::to_string(conv(a + 1 + mode * 2 + 2 + cur, mode * 2 + 2)) + "\n";
			break;
		case 0xEA:
			fl.read((char*)&a, mode * 2 + 2);
			result += "jmp ";
			fl.read((char*)&lb, 2);
			result += std::to_string((lb)) + ":" + std::to_string(a) + "\n";
			break;
		case 0xEB:
			fl.read((char*)&a, 1);
			result += "jmp short ";
			if (conv(a, 1) >= 0) result += "+";
			result += std::to_string(conv(a + 2 + cur, 1)) + "\n";
			break;
		case 0xEC:
			result += "in al, dx\n";
			break;
		case 0xED:
			result += "in " + REG_GET(op_size, 0) + ", dx\n";
			break;
		case 0xEE:
			result += "out dx, al\n";
			break;
		case 0xEF:
			result += "out dx, " + REG_GET(op_size, 0) + "\n";
			break;
		case 0xF2:
			rep_pr = "repnz ";
			continue;
		case 0xF3:
			rep_pr = "repz ";
			continue;
		case 0xF4:
			result += "hlt\n";
			break;
		case 0xF5:
			result += "cmc\n";
			break;
		case 0xF6:
			op_size = 8;
			fl.read((char*)&a, 1);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "test ";
				fl.read((char*)&a, op_size / 8);
				fl.seekg(-(op_size / 8), fl.cur);
				rep_pr = ", " + std::to_string(a) + "\n";
				a = 10;
				break;
			case 1:
				result += "test ";
				fl.read((char*)&a, op_size / 8);
				fl.seekg(-(op_size / 8), fl.cur);
				rep_pr = ", " + std::to_string(a) + "\n";
				a = 10;
				break;
			case 2:
				result += "not ";
				break;
			case 3:
				result += "neg ";
				break;
			case 4:
				result += "mul ";
				break;
			case 5:
				result += "imul ";
				break;
			case 6:
				result += "div ";
				break;
			case 7:
				result += "idiv ";
				break;
			default:
				break;
			}
			fl.seekg(-1, fl.cur);
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, a == 10) + rep_pr;
			if (a == 10)
				fl.seekg((op_size / 8), fl.cur);
			rep_pr = "";
			break;
		case 0xF7:
			fl.read((char*)&a, 1);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "test ";
				fl.read((char*)&a, op_size / 8);
				fl.seekg(-(op_size / 8), fl.cur);
				rep_pr = ", " + std::to_string(a) + "\n";
				a = 10;
				break;
			case 1:
				result += "test ";
				fl.read((char*)&a, op_size / 8);
				fl.seekg(-(op_size / 8), fl.cur);
				rep_pr = ", " + std::to_string(a) + "\n";
				a = 10;
				break;
			case 2:
				result += "not ";
				break;
			case 3:
				result += "neg ";
				break;
			case 4:
				result += "mul ";
				break;
			case 5:
				result += "imul ";
				break;
			case 6:
				result += "div ";
				break;
			case 7:
				result += "idiv ";
				break;
			default:
				break;
			}
			fl.seekg(-1, fl.cur);
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111, a == 10) + rep_pr;
			if (a == 10)
				fl.seekg((op_size / 8), fl.cur);
			rep_pr = "";
			break;

		case 0xF8:
			result += "clc\n";
			break;
		case 0xF9:
			result += "stc\n";
			break;
		case 0xFA:
			result += "cli\n";
			break;
		case 0xFB:
			result += "sti\n";
			break;
		case 0xFC:
			result += "cld\n";
			break;
		case 0xFD:
			result += "std\n";
			break;
		case 0xFE:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "inc ";
				break;
			case 1:
				result += "dec ";
				break;
			case 2:
				result += "call ";
				break;
			case 3:
				result += "callf ";
				break;
			case 4:
				result += "jmp ";
				break;
			case 5:
				result += "jmpf ";
				break;
			case 6:
				result += "push ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, 8, addr_size, fl, 1, 1, 0b11000111);
			break;
		case 0xFF:
			fl.read((char*)&a, 1);
			fl.seekg(-1, fl.cur);
			a &= 0b00111000;
			a >>= 3;
			switch (a)
			{
			case 0:
				result += "inc ";
				break;
			case 1:
				result += "dec ";
				break;
			case 2:
				result += "call ";
				break;
			case 3:
				result += "callf ";
				break;
			case 4:
				result += "jmp ";
				break;
			case 5:
				result += "jmpf ";
				break;
			case 6:
				result += "push ";
				break;
			default:
				break;
			}
			result += parse_ops(mode, seg_reg, op_size, addr_size, fl, 1, 1, 0b11000111);
			break;
		case 0x0F:
			fl.read((char*)buffer, 1);
			switch (*buffer)
			{
			case 0xb6:
				result += "movzx " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF, false, false, 16);
				break;
			case 0xb7:
				result += "movzx " + parse_ops(mode, seg_reg, op_size, addr_size, fl, 2, -1, 0xFF, false, false, 32);
				break;
			default:
				break;
			}
			break;
		default:
			if (op_size != (1 << (mode + 4)) || rep_pr == "")
				result += "db " + std::to_string(last_byte) + "\n";
			result += "db " + std::to_string(*buffer) + "\n";
			seg_reg = 3;
			break;
		};
	ennnnd:
		result += ";+" + std::to_string(cur) + " : ";
		long long cr = fl.tellg();
		fl.seekg(cur, fl.beg);
		for (; cur < cr; cur++) {
			unsigned char a;
			fl.read((char*)&a, 1);
			result += get_hex(a);
		}
		result += "\n";
		seg_reg = 3;
		op_size = (1 << (mode + 4));
		addr_size = (1 << (mode + 4));
		read = false;
	}
	std::string q;
	q.resize(result.length());
	int z = 0;
	for (size_t i = 0; i < result.length(); i++)
	{
		if (result[i] == 0x7F)
		{
			i += 1; continue;
		}
		q[z++] = result[i];
	}
	q.resize(z);
	free(buffer);
	return q;
}

char az[256] = { 0 };
bool prepared = false;
void prepare()
{
	for (int i = 'a'; i <= 'z'; i++)
		az[i] = i - 'a' + 10;
	for (int i = 'A'; i <= 'Z'; i++)
		az[i] = i - 'A' + 10;
	for (int i = '0'; i <= '1'; i++)
		az[i] = i - '0';
}


//Builds a flexible structure from generated assembler code.
std::vector<el> build_structure(const std::string& asms)
{
	if (!prepared)
		prepare();
	std::vector<el> res;
	size_t idx = 0;
	while (1)
	{
		/*
			; comment								\n
			...
			; comment								\n
			command									\n
			;+offset : HEX REPRESENTATION OF CODE	\n
		*/
		if (idx >= asms.length() - 1) break;
		while (asms[idx] == ';') {
			while (asms[++idx] != '\n');
			idx++;
		}
		size_t idx1 = idx;
		while (asms[++idx] != '\n');
		std::string cmd = asms.substr(idx1, idx - idx1);
		idx++;
		el e;
		e.cmd = cmd;
		idx += 2;
		idx1 = idx;
		while (asms[++idx] != ' ');
		std::string offs = asms.substr(idx1, idx - idx1);
		idx++;
		while (asms[++idx] != ' ');
		idx++; idx1 = idx;
		while (asms[++idx] != '\n');
		std::string bts = asms.substr(idx1, idx - idx1);
		++idx;
		for (size_t i = 0; i < bts.length() / 2; i++) {
			unsigned char z = (az[(int)bts[i * 2]] * 16) + (az[(int)bts[i * 2 + 1]]);
			e.bytes.push_back(z);
		}
		e.offset = atoi(offs.c_str());
		res.push_back(e);
	}
	return res;
}
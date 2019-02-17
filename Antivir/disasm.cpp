#include <string>
#include <fstream>
#include "disasm.h"

std::vector<std::string> opcodes_names = { "mov" };
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

std::vector<std::string> reg8_names = {
	"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
};

void disasm_init() {
}

void init_transitions()
{

}

std::vector<std::string> bytes_names_by_op_size = { "-", "b", "w", "d" };
std::vector<int> addr_overrides = { 32, 16, 32 };
std::vector<int> addr_overrides_1 = { 32, 16, 64 };
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
std::vector<std::string> bytes_names(65);
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
	int seg_reg = 3, op_size = 16;
	unsigned char last_byte = 0; std::string rep_pr = "";
	while (1) {
		last_byte = *buffer; int lb = 0;
		unsigned long long a = 0;
		fl.read((char*)buffer, 1);

		if (fl.eof())
			break;
		switch (*buffer)
		{
		case 0x0:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "add " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "add [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			}
			break;
		case 0x1:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "add " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "add [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			}
			break;
		case 0x2:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "add " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "add" + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x3:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "add " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "add " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x4:
			fl.read((char*)&a, 1);
			result += "add al, " + std::to_string(a) + "\n";
			break;
		case 0x5:
			fl.read((char*)&a, op_size / 8);
			result += "add " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x8:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "or " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "or [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			}
			break;
		case 0x9:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "or " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "or [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			}
			break;
		case 0xA:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "or " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "or" + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0xB:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "or " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "or " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0xC:
			fl.read((char*)&a, 1);
			result += "or al, " + std::to_string(a) + "\n";
			break;
		case 0xD:
			fl.read((char*)&a, op_size / 8);
			result += "or " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x0 + 0x0010:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "adc " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "adc [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			}
			break;
		case 0x1 + 0x0010:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "adc " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "adc [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			}
			break;
		case 0x2 + 0x0010:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "adc " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "adc" + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x3 + 0x0010:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "adc " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "adc " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x4 + 0x0010:
			fl.read((char*)&a, 1);
			result += "adc al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x0010:
			fl.read((char*)&a, op_size / 8);
			result += "adc " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x0 + 0x0018:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "sbb " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "sbb [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			}
			break;
		case 0x1 + 0x0018:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "sbb " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "sbb [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			}
			break;
		case 0x2 + 0x0018:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "sbb " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "sbb " + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x3 + 0x0018:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "sbb " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "sbb " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x4 + 0x0018:
			fl.read((char*)&a, 1);
			result += "sbb al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x0018:
			fl.read((char*)&a, op_size / 8);
			result += "sbb " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break;
		case 0x0 + 0x0020:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "and " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "and [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			}
			break;
		case 0x1 + 0x0020:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "and " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "and [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			}
			break;
		case 0x2 + 0x0020:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "and " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "and " + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x3 + 0x0020:
			fl.read((char*)buffer, 1);
			if ((*buffer & 0b11000000) >> 6 == 0b11)
				result += "and " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
			else {
				fl.read((char*)&a, mode * 2 + 2);
				result += "and " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
			}
			break;
		case 0x4 + 0x0020:
			fl.read((char*)&a, 1);
			result += "and al, " + std::to_string(a) + "\n";
			break;
		case 0x5 + 0x0020:
			fl.read((char*)&a, op_size / 8);
			result += "and " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
			break; case 0x0 + 0x0038:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "cmp " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "cmp [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				}
				break;
			case 0x1 + 0x0038:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "cmp " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "cmp [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				}
				break;
			case 0x2 + 0x0038:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "cmp " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "cmp" + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
				}
				break;
			case 0x3 + 0x0038:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "cmp " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "cmp " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
				}
				break;
			case 0x4 + 0x0038:
				fl.read((char*)&a, 1);
				result += "cmp al, " + std::to_string(a) + "\n";
				break;
			case 0x5 + 0x0038:
				fl.read((char*)&a, op_size / 8);
				result += "cmp " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
				break;
			case 0x26: // ES Override
				seg_reg = 0;
				result += ";ES Override\n";
				continue;
			case 0x2E: // CS Override
				seg_reg = 1;
				result += ";CS Override\n";
				continue;
			case 0x28:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "sub " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else {
					
					fl.read((char*)&a, mode * 2 + 2);
					result += "sub [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				}
				break;
			case 0x29:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "sub " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "sub [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				}
				break;
			case 0x2A:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "sub " + reg8_names[(*buffer & 0b111)] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "sub" + reg8_names[(*buffer & 0b111000) >> 3] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
				}
				break;
			case 0x2B:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "sub " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else {
					fl.read((char*)&a, mode * 2 + 2);
					result += "sub " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(a) + "]\n";
				}
				break;
			case 0x2C:
				fl.read((char*)&a, 1);
				result += "sub al, " + std::to_string(a) + "\n";
				break;
			case 0x2D:
				fl.read((char*)&a, op_size / 8);
				result += "sub " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
				break;
			case 0x30:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "xor " + reg8_names[*buffer & 0b111] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else if ((*buffer & 0b11000000) >> 6 == 0b00) {
					char addr[8] = { 0 };
					fl.read((char*)&addr, mode * 2 + 2);
					result += "xor [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&addr) + "], " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				}
				break;
			case 0x31:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "xor " + REG_GET(op_size, *buffer & 0b111) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else if ((*buffer & 0b11000000) >> 6 == 0b00) {
					char addr[8] = { 0 };
					fl.read((char*)&addr, mode * 2 + 2);
					result += "xor [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&addr) + "], " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				}
				break;
			case 0x32:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "xor " + reg8_names[*buffer & 0b111] + ", " + reg8_names[(*buffer & 0b111000) >> 3] + "\n";
				else if ((*buffer & 0b11000000) >> 6 == 0b00) {
					char addr[8] = { 0 };
					fl.read((char*)&addr, mode * 2 + 2);
					result += "xor " + reg8_names[(*buffer & 0b111000) >> 3] + ", " + "[" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&addr) + "]\n";
				}
				break;
			case 0x33:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "xor " + REG_GET(op_size, *buffer & 0b111) + ", " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + "\n";
				else if ((*buffer & 0b11000000) >> 6 == 0b00) {
					char addr[8] = { 0 };
					fl.read((char*)&addr, mode * 2 + 2);
					result += "xor " + REG_GET(op_size, (*buffer & 0b111000) >> 3) + ", " + "[" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&addr) + "]\n";
				}
				break;
			case 0x34:
				fl.read((char*)&a, 1);
				result += "xor al, " + std::to_string(a) + "\n";
				break;
			case 0x35:

				fl.read((char*)&a, mode * 2 + 2);
				result += "xor " + REG_GET(op_size, 0) + ", " + std::to_string(a) + "\n";
				break;
			case 0x36: // SS Override
				seg_reg = 2;
				result += ";SS Override\n";
				continue;
			case 0x3E: // DS Override
				seg_reg = 3;
				result += ";DS Override\n";
				continue;
			case 0x48:
				op_size = 64;
				result += ";Address size override 64\n";
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
				result += ";Address size override\n";
				continue;
			case 0x80:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
				{
					unsigned long long ab = 0;
					fl.read((char*)&ab, 1);
					switch (((*buffer & 0b111000) >> 3))
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
					result += reg8_names[*buffer & 0b111] + ", " + std::to_string(ab) + "\n";
				}
				else
				{
					unsigned long long abz = 0;
					fl.read((char*)&abz, mode * 2 + 2);
					unsigned long long ab = 0;
					fl.read((char*)&ab, 1);
					switch (((*buffer & 0b111000) >> 3))
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
					result += "byte [" + SREG_GET(seg_reg) + ":" + std::to_string(abz) + "], " + std::to_string(ab) + "\n";
				}
				break;
			case 0x81:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
				{
					unsigned long long ab = 0;
					fl.read((char*)&ab, mode * 2 + 2);
					switch (((*buffer & 0b111000) >> 3))
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
					result += REG_GET(op_size, *buffer & 0b111) + ", " + std::to_string(ab) + "\n";
				}
				else
				{
					unsigned long long abz = 0;
					fl.read((char*)&abz, mode * 2 + 2);
					unsigned long long ab = 0;
					fl.read((char*)&ab, mode * 2 + 2);
					switch (((*buffer & 0b111000) >> 3))
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
					result += "[" + SREG_GET(seg_reg) + ":" + std::to_string(abz) + "], " + std::to_string(ab) + "\n";
				}
				break;
			case 0x83:

				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
				{
					unsigned long long ab = 0;
					fl.read((char*)&ab, 1);
					switch (((*buffer & 0b111000) >> 3))
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
					result += REG_GET(op_size, *buffer & 0b111) + ", " + std::to_string(ab) + "\n";
				}
				else
				{
					unsigned long long abz = 0;
					fl.read((char*)&abz, mode * 2 + 2);
					unsigned long long ab = 0;
					fl.read((char*)&ab, 1);
					switch (((*buffer & 0b111000) >> 3))
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
					result += "byte [" + SREG_GET(seg_reg) + ":" + std::to_string(abz) + "], " + std::to_string(ab) + "\n";
				}
				break;
			case 0x88:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 11)
					result += "mov " + reg8_names[*buffer & 0b111] + ", " + reg8_names[((*buffer & 0b111000) >> 3)] + "\n";
				else {
					char mem[8] = { 0 };
					fl.read((char*)&mem, mode * 2 + 2);
					result += "mov [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&mem) + "]" + ", " + reg8_names[((*buffer & 0b111000) >> 3)] + "\n";
				}
				break;
			case 0x89:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 11)
					result += "mov " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, ((*buffer & 0b111000) >> 3)) + "\n";
				else {
					char mem[8] = { 0 };
					fl.read((char*)&mem, mode * 2 + 2);
					result += "mov [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&mem) + "], " + REG_GET(op_size, ((*buffer & 0b111000) >> 3)) + "\n";
				}
				break;
			case 0x8A:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "mov " + reg8_names[*buffer & 0b111] + ", " + reg8_names[((*buffer & 0b111000) >> 3)] + "\n";
				else {
					char mem[8] = { 0 };
					fl.read((char*)&mem, mode * 2 + 2);
					result += "mov " + reg8_names[((*buffer & 0b111000) >> 3)] + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&mem) + "]\n";
				}
				break;
			case 0x8B:
				fl.read((char*)buffer, 1);
				if ((*buffer & 0b11000000) >> 6 == 0b11)
					result += "mov " + REG_GET(op_size, (*buffer & 0b111)) + ", " + REG_GET(op_size, ((*buffer & 0b111000) >> 3)) + "\n";
				else {
					char mem[8] = { 0 };
					fl.read((char*)&mem, mode * 2 + 2);
					result += "mov " + REG_GET(op_size, ((*buffer & 0b111000) >> 3)) + ", [" + SREG_GET(seg_reg) + ":" + std::to_string(*(unsigned long long*)&mem) + "]\n";
				}
				break;
			case 0x8C:
				fl.read((char*)buffer, 1);
				result += "mov " + REG16_GET((*buffer & 0b111)) + ", " + SREG_GET(((*buffer & 0b111000) >> 3)) + "\n";

				break;
			case 0x8E:
				fl.read((char*)buffer, 1);
				result += "mov " + SREG_GET(((*buffer & 0b111000) >> 3)) + ", " + REG16_GET((*buffer & 0b111)) + "\n";

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
			case 0xA0:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "mov " + REG_GET(8, 0) + ",  [" + SREG_GET(seg_reg) + ":" + std::to_string(*((unsigned int*)buffer)) + "]\n";
				break;
			case 0xA1:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "mov " + REG_GET(op_size, 0) + ",  [" + SREG_GET(seg_reg) + ":" + std::to_string(*((unsigned int*)buffer)) + "]\n";

				break;
			case 0xA2:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "mov  [" + SREG_GET(seg_reg) + ":" + std::to_string(*((unsigned int*)buffer)) + "]" + ", " + REG_GET(8, 0) + "\n";
				break;
			case 0xA3:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "mov  [" + SREG_GET(seg_reg) + ":" + std::to_string(*((unsigned int*)buffer)) + "]" + ", " + REG_GET(op_size, 0) + "\n";
				break;

			case 0xA4:
				result += "movsb\n";

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
				result += "lods" + bytes_names_by_op_size[log2c(op_size) - 2] + "\n";
				rep_pr = "";
				break;
			case 0xB0:
				fl.read((char*)buffer, 1);
				result += "mov al, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB1:
				fl.read((char*)buffer, 1);
				result += "mov cl, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB2:
				fl.read((char*)buffer, 1);
				result += "mov dl, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB3:
				fl.read((char*)buffer, 1);
				result += "mov bl, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB4:
				fl.read((char*)buffer, 1);
				result += "mov ah, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB5:
				fl.read((char*)buffer, 1);
				result += "mov ch, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB6:
				fl.read((char*)buffer, 1);
				result += "mov dh, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB7:
				fl.read((char*)buffer, 1);
				result += "mov bh, " + std::to_string(*buffer) + "\n";
				break;
			case 0xB8:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xB9:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBA:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBB:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBC:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBD:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBE:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
				break;
			case 0xBF:
				lb = *buffer;
				memset(buffer, 0, 8);
				fl.read((char*)buffer, op_size >> 3);
				result += "mov " + REG_GET(op_size, lb - 0xB8) + ", " + std::to_string(*(unsigned long long*)(buffer)) + "\n";
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
			case 0xE8:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "call ";
				if (*(int*)buffer >= 0) result += "+";
				result += std::to_string(*(int*)buffer) + "\n";
				break;
			case 0xE9:
				fl.read((char*)buffer, mode * 2 + 2);
				result += "jmp far ";
				if (*(int*)buffer >= 0) result += "+";
				result += std::to_string(*(int*)buffer) + "\n";
				break;
			case 0xEB:
				fl.read((char*)buffer, 1);
				result += "jmp near ";
				if (*(char*)buffer >= 0) result += "+";
				result += std::to_string(*(char*)buffer) + "\n";
				break;
			case 0xF8:
				result += "clc\n";

				break;
			case 0xF9:
				result += "stc\n";

				break;
			case 0xF2:
				rep_pr = "repnz ";
				continue;
			case 0xF3:
				rep_pr = "repz ";
				continue;
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

			default: {
				if (op_size != (1 << (mode + 4)) || rep_pr == "")
					result += "db " + std::to_string(last_byte) + "\n";
				result += "db " + std::to_string(*buffer) + "\n";

				break;
			}
		};
		op_size = (1 << (mode + 4));
	}
	free(buffer);
	return result;
}
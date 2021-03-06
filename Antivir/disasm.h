#pragma once
#ifndef _DISASM_H
#define _DISASM_H 1
/*
	disasm.h - disassembler and other structures. Converts bytes to assembler code.
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
#include <vector>

#define REG16_OFFSET 2
#define REG32_OFFSET 3
#define REG64_OFFSET 4
#define SREG_OFFSET 40
#define REG_T_SIZE 5
#define REG_GET(a, b) (reg_names[(b)*REG_T_SIZE + 2 + (log2c(a)-4)])
#define REG16_GET(f) (reg_names[REG_T_SIZE * f + REG16_OFFSET])
#define REG32_GET(f) (reg_names[REG_T_SIZE * f + REG32_OFFSET])
#define REG64_GET(f) (reg_names[REG_T_SIZE * f + REG64_OFFSET])


/*
BITS 32 - OPCODE 66 PREFIX

mov reg16, reg16
OPCODE: 89,
11000000
  ...^^^
mov reg16, sreg
OPCODE: 8C,
11000000
  ...^^^
mov reg16, mem
OPCODE: 8B,
00^^^110, ADDR
*/
#define MODE_16 0
#define MODE_32 1
#define MODE_64 2
std::string disasm_code(std::string filename, int mode);
void init_transitions();
void disasm_init();
typedef struct {
	long long offset;
	std::vector<unsigned char> bytes;
	std::string cmd;
}el;
std::vector<el> build_structure(const std::string& asms);
#endif
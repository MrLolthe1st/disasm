[BITS 32]
mov     es, ax          ; es:0 -> top - 512
sub     ax, 2048 / 16   ; reserve 2048 bytes for the stack
mov     ss, ax          ; ss:0 -> top - 512 - 2048
mov     sp, 2048
sub eax, 65537
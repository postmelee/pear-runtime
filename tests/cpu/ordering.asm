; SPDX-License-Identifier: MIT
; Original Pear x64 measured sequences. RCX/RDX point to separate aligned cells.
BITS 64
DEFAULT REL
section .text code align=16
global pear_locked, pear_publish, pear_observe, pear_buffer, pear_fenced
pear_locked:
    mov eax, 1
    lock xadd [rcx], eax
    ret
pear_publish:
    mov dword [rcx], 1
    mov dword [rdx], 1
    xor eax, eax
    ret
pear_observe:
    mov eax, [rdx]
    shl eax, 1
    mov r8d, [rcx]
    or eax, r8d
    ret
pear_buffer:
    mov dword [rcx], 1
    mov eax, [rdx]
    ret
pear_fenced:
    mov dword [rcx], 1
    mfence
    mov eax, [rdx]
    ret

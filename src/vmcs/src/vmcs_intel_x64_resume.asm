;
; Bareflank Hypervisor
;
; Copyright (C) 2015 Assured Information Security, Inc.
; Author: Rian Quinn        <quinnr@ainfosec.com>
; Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
;
; This library is free software; you can redistribute it and/or
; modify it under the terms of the GNU Lesser General Public
; License as published by the Free Software Foundation; either
; version 2.1 of the License, or (at your option) any later version.
;
; This library is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
; Lesser General Public License for more details.
;
; You should have received a copy of the GNU Lesser General Public
; License along with this library; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

bits 64
default rel

%define VMCS_GUEST_RSP 0x0000681C
%define VMCS_GUEST_RIP 0x0000681E

global vmcs_resume:function

section .text

; Resume VMCS
;
; Resumes the execution of an already launched VMCS. Note that this function
; should not return. If it does, an error has occurred.
;
vmcs_resume:

    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov rsi, VMCS_GUEST_RSP
    vmwrite rsi, [rdi + 0x080]
    mov rsi, VMCS_GUEST_RIP
    vmwrite rsi, [rdi + 0x078]

    movdqa xmm7,  [rdi + 0x1A0]
    movdqa xmm6,  [rdi + 0x180]
    movdqa xmm5,  [rdi + 0x160]
    movdqa xmm4,  [rdi + 0x140]
    movdqa xmm3,  [rdi + 0x120]
    movdqa xmm2,  [rdi + 0x100]
    movdqa xmm1,  [rdi + 0x0E0]
    movdqa xmm0,  [rdi + 0x0C0]

    mov r15, [rdi + 0x070]
    mov r14, [rdi + 0x068]
    mov r13, [rdi + 0x060]
    mov r12, [rdi + 0x058]
    mov r11, [rdi + 0x050]
    mov r10, [rdi + 0x048]
    mov r9,  [rdi + 0x040]
    mov r8,  [rdi + 0x038]
    mov rsi, [rdi + 0x028]
    mov rbp, [rdi + 0x020]
    mov rdx, [rdi + 0x018]
    mov rcx, [rdi + 0x010]
    mov rbx, [rdi + 0x008]
    mov rax, [rdi + 0x000]

    mov rdi, [rdi + 0x030]

    vmresume

; We should never get this far. If we do, it's because the resume failed. If
; happens, we return so that we can throw an exception and tell the user that
; something really bad happened.

    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx

    ret

//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfgsl.h>
#include <bfdebug.h>

#include <intrinsics/portio_x64.h>

extern "C" uint8_t
__inb(uint16_t port) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    abort();
}

extern "C" uint16_t
__inw(uint16_t port) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    abort();
}

extern "C" uint32_t
__ind(uint16_t port) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    abort();
}

extern "C" void
__insb(uint16_t port, uint64_t m8) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    abort();
}

extern "C" void
__insw(uint16_t port, uint64_t m16) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    abort();
}

extern "C" void
__insd(uint16_t port, uint64_t m32) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    abort();
}

extern "C" void
__insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

extern "C" void
__inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

extern "C" void
__insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

extern "C" void
__outb(uint16_t port, uint8_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__outw(uint16_t port, uint16_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__outd(uint16_t port, uint32_t val) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - val: " << view_as_pointer(val) << '\n';
    abort();
}

extern "C" void
__outsb(uint16_t port, uint64_t m8) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    abort();
}

extern "C" void
__outsw(uint16_t port, uint64_t m16) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    abort();
}

extern "C" void
__outsd(uint16_t port, uint64_t m32) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    abort();
}

extern "C" void
__outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m8: " << view_as_pointer(m8) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

extern "C" void
__outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m16: " << view_as_pointer(m16) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

extern "C" void
__outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept
{
    std::cerr << __FUNC__ << " called with: " << '\n';
    std::cerr << "    - port: " << view_as_pointer(port) << '\n';
    std::cerr << "    - m32: " << view_as_pointer(m32) << '\n';
    std::cerr << "    - count: " << view_as_pointer(count) << '\n';
    abort();
}

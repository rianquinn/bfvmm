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

#ifndef PORTIO_X64_H
#define PORTIO_X64_H

#include <bfgsl.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" EXPORT_INTRINSICS uint8_t _inb(uint16_t port) noexcept;
extern "C" EXPORT_INTRINSICS uint16_t _inw(uint16_t port) noexcept;
extern "C" EXPORT_INTRINSICS uint32_t _ind(uint16_t port) noexcept;

extern "C" EXPORT_INTRINSICS void _insb(uint16_t port, uint64_t m8) noexcept;
extern "C" EXPORT_INTRINSICS void _insw(uint16_t port, uint64_t m16) noexcept;
extern "C" EXPORT_INTRINSICS void _insd(uint16_t port, uint64_t m32) noexcept;

extern "C" EXPORT_INTRINSICS void _insbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" EXPORT_INTRINSICS void _inswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" EXPORT_INTRINSICS void _insdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

extern "C" EXPORT_INTRINSICS void _outb(uint16_t port, uint8_t val) noexcept;
extern "C" EXPORT_INTRINSICS void _outw(uint16_t port, uint16_t val) noexcept;
extern "C" EXPORT_INTRINSICS void _outd(uint16_t port, uint32_t val) noexcept;

extern "C" EXPORT_INTRINSICS void _outsb(uint16_t port, uint64_t m8) noexcept;
extern "C" EXPORT_INTRINSICS void _outsw(uint16_t port, uint64_t m16) noexcept;
extern "C" EXPORT_INTRINSICS void _outsd(uint16_t port, uint64_t m32) noexcept;

extern "C" EXPORT_INTRINSICS void _outsbrep(uint16_t port, uint64_t m8, uint32_t count) noexcept;
extern "C" EXPORT_INTRINSICS void _outswrep(uint16_t port, uint64_t m16, uint32_t count) noexcept;
extern "C" EXPORT_INTRINSICS void _outsdrep(uint16_t port, uint64_t m32, uint32_t count) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace portio
{
    using port_addr_type = uint16_t;
    using port_8bit_type = uint8_t;
    using port_16bit_type = uint16_t;
    using port_32bit_type = uint32_t;
    using integer_pointer = uintptr_t;
    using size_type = uint32_t;

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto inb(P port) noexcept { return _inb(gsl::narrow_cast<port_addr_type>(port)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto inw(P port) noexcept { return _inw(gsl::narrow_cast<port_addr_type>(port)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto ind(P port) noexcept { return _ind(gsl::narrow_cast<port_addr_type>(port)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insb(P port, integer_pointer m8) noexcept { return _insb(gsl::narrow_cast<port_addr_type>(port), m8); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insw(P port, integer_pointer m16) noexcept { return _insw(gsl::narrow_cast<port_addr_type>(port), m16); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insd(P port, integer_pointer m32) noexcept { return _insd(gsl::narrow_cast<port_addr_type>(port), m32); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insb(P port, void *m8) noexcept { return _insb(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insw(P port, void *m16) noexcept { return _insw(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insd(P port, void *m32) noexcept { return _insd(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insbrep(P port, integer_pointer m8, size_type count) noexcept { return _insbrep(gsl::narrow_cast<port_addr_type>(port), m8, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto inswrep(P port, integer_pointer m16, size_type count) noexcept { return _inswrep(gsl::narrow_cast<port_addr_type>(port), m16, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insdrep(P port, integer_pointer m32, size_type count) noexcept { return _insdrep(gsl::narrow_cast<port_addr_type>(port), m32, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insbrep(P port, void *m8, size_type count) noexcept { return _insbrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8), count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto inswrep(P port, void *m16, size_type count) noexcept { return _inswrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16), count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    auto insdrep(P port, void *m32, size_type count) noexcept { return _insdrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32), count); }

    template<
        typename P,
        typename T,
        typename = std::enable_if<std::is_integral<P>::value>,
        typename = std::enable_if<std::is_integral<T>::value>
        >
    void outb(P port, T val) noexcept { _outb(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_8bit_type>(val)); }

    template<
        typename P,
        typename T,
        typename = std::enable_if<std::is_integral<P>::value>,
        typename = std::enable_if<std::is_integral<T>::value>
        >
    void outw(P port, T val) noexcept { _outw(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_16bit_type>(val)); }

    template<
        typename P,
        typename T,
        typename = std::enable_if<std::is_integral<P>::value>,
        typename = std::enable_if<std::is_integral<T>::value>
        >
    void outd(P port, T val) noexcept { _outd(gsl::narrow_cast<port_addr_type>(port), gsl::narrow_cast<port_32bit_type>(val)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsb(P port, integer_pointer m8) noexcept { _outsb(gsl::narrow_cast<port_addr_type>(port), m8); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsw(P port, integer_pointer m16) noexcept { _outsw(gsl::narrow_cast<port_addr_type>(port), m16); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsd(P port, integer_pointer m32) noexcept { _outsd(gsl::narrow_cast<port_addr_type>(port), m32); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsb(P port, void *m8) noexcept { _outsb(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsw(P port, void *m16) noexcept { _outsw(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsd(P port, void *m32) noexcept { _outsd(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32)); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsbrep(P port, integer_pointer m8, size_type count) noexcept { _outsbrep(gsl::narrow_cast<port_addr_type>(port), m8, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outswrep(P port, integer_pointer m16, size_type count) noexcept { _outswrep(gsl::narrow_cast<port_addr_type>(port), m16, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsdrep(P port, integer_pointer m32, size_type count) noexcept { _outsdrep(gsl::narrow_cast<port_addr_type>(port), m32, count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsbrep(P port, void *m8, size_type count) noexcept { _outsbrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m8), count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outswrep(P port, void *m16, size_type count) noexcept { _outswrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m16), count); }

    template<typename P, typename = std::enable_if<std::is_integral<P>::value>>
    void outsdrep(P port, void *m32, size_type count) noexcept { _outsdrep(gsl::narrow_cast<port_addr_type>(port), reinterpret_cast<integer_pointer>(m32), count); }
}
}

// *INDENT-ON*

#endif

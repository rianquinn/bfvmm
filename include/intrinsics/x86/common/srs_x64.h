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

#ifndef SRS_X64_H
#define SRS_X64_H

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifdef STATIC_INTRINSICS
#define EXPORT_INTRINSICS
#else
#ifdef COMPILING_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" EXPORT_INTRINSICS uint16_t _read_es(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_es(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_cs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ss(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ss(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ds(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ds(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_fs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_fs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_gs(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_gs(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_ldtr(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_ldtr(uint16_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint16_t _read_tr(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_tr(uint16_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace segment_register
{

using type = uint16_t;

namespace es
{
    inline auto get() noexcept
    { return _read_es(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_es(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_es(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_es(gsl::narrow_cast<type>(set_bits(_read_es(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_es(), from)); }

        inline void set(bool val) noexcept
        { _write_es(gsl::narrow_cast<type>(val ? set_bit(_read_es(), from) : clear_bit(_read_es(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_es(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_es(gsl::narrow_cast<type>(set_bits(_read_es(), mask, val << from))); }
    }
}

namespace cs
{
    inline auto get() noexcept
    { return _read_cs(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_cs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_cs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_cs(gsl::narrow_cast<type>(set_bits(_read_cs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_cs(), from)); }

        inline void set(bool val) noexcept
        { _write_cs(gsl::narrow_cast<type>(val ? set_bit(_read_cs(), from) : clear_bit(_read_cs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_cs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_cs(gsl::narrow_cast<type>(set_bits(_read_cs(), mask, val << from))); }
    }
}

namespace ss
{
    inline auto get() noexcept
    { return _read_ss(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_ss(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ss(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ss(gsl::narrow_cast<type>(set_bits(_read_ss(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_ss(), from)); }

        inline void set(bool val) noexcept
        { _write_ss(gsl::narrow_cast<type>(val ? set_bit(_read_ss(), from) : clear_bit(_read_ss(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ss(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ss(gsl::narrow_cast<type>(set_bits(_read_ss(), mask, val << from))); }
    }
}

namespace ds
{
    inline auto get() noexcept
    { return _read_ds(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_ds(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ds(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ds(gsl::narrow_cast<type>(set_bits(_read_ds(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_ds(), from)); }

        inline void set(bool val) noexcept
        { _write_ds(gsl::narrow_cast<type>(val ? set_bit(_read_ds(), from) : clear_bit(_read_ds(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ds(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ds(gsl::narrow_cast<type>(set_bits(_read_ds(), mask, val << from))); }
    }
}

namespace fs
{
    inline auto get() noexcept
    { return _read_fs(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_fs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_fs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_fs(gsl::narrow_cast<type>(set_bits(_read_fs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_fs(), from)); }

        inline void set(bool val) noexcept
        { _write_fs(gsl::narrow_cast<type>(val ? set_bit(_read_fs(), from) : clear_bit(_read_fs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_fs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_fs(gsl::narrow_cast<type>(set_bits(_read_fs(), mask, val << from))); }
    }
}

namespace gs
{
    inline auto get() noexcept
    { return _read_gs(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_gs(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_gs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_gs(gsl::narrow_cast<type>(set_bits(_read_gs(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_gs(), from)); }

        inline void set(bool val) noexcept
        { _write_gs(gsl::narrow_cast<type>(val ? set_bit(_read_gs(), from) : clear_bit(_read_gs(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_gs(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_gs(gsl::narrow_cast<type>(set_bits(_read_gs(), mask, val << from))); }
    }
}

namespace ldtr
{
    inline auto get() noexcept
    { return _read_ldtr(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_ldtr(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ldtr(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ldtr(gsl::narrow_cast<type>(set_bits(_read_ldtr(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_ldtr(), from)); }

        inline void set(bool val) noexcept
        { _write_ldtr(gsl::narrow_cast<type>(val ? set_bit(_read_ldtr(), from) : clear_bit(_read_ldtr(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_ldtr(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_ldtr(gsl::narrow_cast<type>(set_bits(_read_ldtr(), mask, val << from))); }
    }
}

namespace tr
{
    inline auto get() noexcept
    { return _read_tr(); }

    template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
    void set(T val) noexcept { _write_tr(gsl::narrow_cast<type>(val)); }

    namespace rpl
    {
        constexpr const auto mask = 0x00000003U;
        constexpr const auto from = 0;
        constexpr const auto name = "rpl";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_tr(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_tr(gsl::narrow_cast<type>(set_bits(_read_tr(), mask, val << from))); }
    }

    namespace ti
    {
        constexpr const auto mask = 0x00000004U;
        constexpr const auto from = 2;
        constexpr const auto name = "ti";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bit(_read_tr(), from)); }

        inline void set(bool val) noexcept
        { _write_tr(gsl::narrow_cast<type>(val ? set_bit(_read_tr(), from) : clear_bit(_read_tr(), from))); }
    }

    namespace index
    {
        constexpr const auto mask = 0x0000FFF8U;
        constexpr const auto from = 3;
        constexpr const auto name = "index";

        inline auto get() noexcept
        { return gsl::narrow_cast<type>(get_bits(_read_tr(), mask) >> from); }

        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_tr(gsl::narrow_cast<type>(set_bits(_read_tr(), mask, val << from))); }
    }
}
}
}

// *INDENT-ON*

#endif

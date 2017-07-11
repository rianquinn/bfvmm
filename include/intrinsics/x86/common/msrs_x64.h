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

#ifndef MSRS_X64_H
#define MSRS_X64_H

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

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

extern "C" EXPORT_INTRINSICS uint64_t _read_msr(uint32_t addr) noexcept;
extern "C" EXPORT_INTRINSICS void _write_msr(uint32_t addr, uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace msrs
{
    using field_type = uint32_t;
    using value_type = uint64_t;

    template<typename A> inline auto get(A addr) noexcept
    { return _read_msr(gsl::narrow_cast<field_type>(addr)); }

    template<typename A, class T> void set(A addr, T val) noexcept
    { _write_msr(gsl::narrow_cast<field_type>(addr), val); }

    namespace ia32_p5_mc_addr
    {
        constexpr const auto addr = 0x00000000UL;
        constexpr const auto name = "ia32_p5_mc_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_p5_mc_type
    {
        constexpr const auto addr = 0x00000001UL;
        constexpr const auto name = "ia32_p5_mc_type";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_tsc
    {
        constexpr const auto addr = 0x00000010UL;
        constexpr const auto name = "ia32_tsc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_apic_base
    {
        constexpr const auto addr = 0x0000001BUL;
        constexpr const auto name = "ia32_apic_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace bsp_flag
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "bsp_flag";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace enable_x2apic
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "enable_x2apic";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace apic_global_enable
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "apic_global_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace apic_base
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "apic_base";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_mperf
    {
        constexpr const auto addr = 0x000000E7UL;
        constexpr const auto name = "ia32_mperf";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace tsc_freq_clock_count
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "tsc_freq_clock_count";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_aperf
    {
        constexpr const auto addr = 0x000000E8UL;
        constexpr const auto name = "ia32_aperf";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace actual_freq_clock_count
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "actual_freq_clock_count";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_mtrrcap
    {
        constexpr const auto addr = 0x000000FEUL;
        constexpr const auto name = "ia32_mtrrcap";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace vcnt
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "vcnt";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace fixed_range_mtrr
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "fixed_range_mtrr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace wc
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "wc";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace smrr
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "smrr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_sysenter_cs
    {
        constexpr const auto addr = 0x00000174UL;
        constexpr const auto name = "ia32_sysenter_cs";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace cs_selector
        {
            constexpr const auto mask = 0x000000000000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "cs_selector";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_sysenter_esp
    {
        constexpr const auto addr = 0x00000175UL;
        constexpr const auto name = "ia32_sysenter_esp";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_sysenter_eip
    {
        constexpr const auto addr = 0x00000176UL;
        constexpr const auto name = "ia32_sysenter_eip";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_mcg_cap
    {
        constexpr const auto addr = 0x00000179UL;
        constexpr const auto name = "ia32_mcg_cap";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace count
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "count";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace mcg_ctl
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "mcg_ctl";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_ext
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "mcg_ext";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_cmci
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "mcg_cmci";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_tes
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "mcg_tes";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_ext_cnt
        {
            constexpr const auto mask = 0x0000000000FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "mcg_ext_cnt";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace mcg_ser
        {
            constexpr const auto mask = 0x0000000001000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "mcg_ser";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_elog
        {
            constexpr const auto mask = 0x0000000004000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "mcg_elog";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace mcg_lmce
        {
            constexpr const auto mask = 0x0000000008000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "mcg_lmce";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_mcg_status
    {
        constexpr const auto addr = 0x0000017AUL;
        constexpr const auto name = "ia32_mcg_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace ripv
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "ripv";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace eipv
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "eipv";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace mcip
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "mcip";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lmce_s
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "lmce_s";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mcg_ctl
    {
        constexpr const auto addr = 0x0000017BUL;
        constexpr const auto name = "ia32_mcg_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pat
    {
        constexpr const auto addr = 0x00000277UL;
        constexpr const auto name = "ia32_pat";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace pa0
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "pa0";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa1
        {
            constexpr const auto mask = 0x0000000000000700ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "pa1";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa2
        {
            constexpr const auto mask = 0x0000000000070000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "pa2";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa3
        {
            constexpr const auto mask = 0x0000000007000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "pa3";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa4
        {
            constexpr const auto mask = 0x0000000700000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "pa4";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa5
        {
            constexpr const auto mask = 0x0000070000000000ULL;
            constexpr const auto from = 40;
            constexpr const auto name = "pa5";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa6
        {
            constexpr const auto mask = 0x0007000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "pa6";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pa7
        {
            constexpr const auto mask = 0x0700000000000000ULL;
            constexpr const auto from = 56;
            constexpr const auto name = "pa7";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            auto get(T val) noexcept
            { return get_bits(val, mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_pat fields:" << bfendl;

            bfdebug << "    - " << pa0::name << " = "
                    << view_as_pointer(pa0::get()) << bfendl;
            bfdebug << "    - " << pa1::name << " = "
                    << view_as_pointer(pa1::get()) << bfendl;
            bfdebug << "    - " << pa2::name << " = "
                    << view_as_pointer(pa2::get()) << bfendl;
            bfdebug << "    - " << pa3::name << " = "
                    << view_as_pointer(pa3::get()) << bfendl;
            bfdebug << "    - " << pa4::name << " = "
                    << view_as_pointer(pa4::get()) << bfendl;
            bfdebug << "    - " << pa5::name << " = "
                    << view_as_pointer(pa5::get()) << bfendl;
            bfdebug << "    - " << pa6::name << " = "
                    << view_as_pointer(pa6::get()) << bfendl;
            bfdebug << "    - " << pa7::name << " = "
                    << view_as_pointer(pa7::get()) << bfendl;
        }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        auto pa(T index)
        {
            switch (index)
            {
                case 0: return pa0::get();
                case 1: return pa1::get();
                case 2: return pa2::get();
                case 3: return pa3::get();
                case 4: return pa4::get();
                case 5: return pa5::get();
                case 6: return pa6::get();
                case 7: return pa7::get();
                default:
                    throw std::runtime_error("unknown pat index");
            }
        }

        template<typename V, class I,
                 typename =  std::enable_if<std::is_integral<V>::value>,
                 typename =  std::enable_if<std::is_integral<I>::value>>
        auto pa(V value, I index)
        {
            switch (index)
            {
                case 0: return pa0::get(value);
                case 1: return pa1::get(value);
                case 2: return pa2::get(value);
                case 3: return pa3::get(value);
                case 4: return pa4::get(value);
                case 5: return pa5::get(value);
                case 6: return pa6::get(value);
                case 7: return pa7::get(value);
                default:
                    throw std::runtime_error("unknown pat index");
            }
        }
    }

    namespace ia32_mc0_ctl
    {
        constexpr const auto addr = 0x00000400UL;
        constexpr const auto name = "ia32_mc0_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc0_status
    {
        constexpr const auto addr = 0x00000401UL;
        constexpr const auto name = "ia32_mc0_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc0_addr
    {
        constexpr const auto addr = 0x00000402UL;
        constexpr const auto name = "ia32_mc0_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc0_misc
    {
        constexpr const auto addr = 0x00000403UL;
        constexpr const auto name = "ia32_mc0_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc1_ctl
    {
        constexpr const auto addr = 0x00000404UL;
        constexpr const auto name = "ia32_mc1_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc1_status
    {
        constexpr const auto addr = 0x00000405UL;
        constexpr const auto name = "ia32_mc1_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc1_addr
    {
        constexpr const auto addr = 0x00000406UL;
        constexpr const auto name = "ia32_mc1_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc1_misc
    {
        constexpr const auto addr = 0x00000407UL;
        constexpr const auto name = "ia32_mc1_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc2_ctl
    {
        constexpr const auto addr = 0x00000408UL;
        constexpr const auto name = "ia32_mc2_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc2_status
    {
        constexpr const auto addr = 0x00000409UL;
        constexpr const auto name = "ia32_mc2_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc2_addr
    {
        constexpr const auto addr = 0x0000040AUL;
        constexpr const auto name = "ia32_mc2_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc2_misc
    {
        constexpr const auto addr = 0x0000040BUL;
        constexpr const auto name = "ia32_mc2_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc3_ctl
    {
        constexpr const auto addr = 0x0000040CUL;
        constexpr const auto name = "ia32_mc3_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc3_status
    {
        constexpr const auto addr = 0x0000040DUL;
        constexpr const auto name = "ia32_mc3_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc3_addr
    {
        constexpr const auto addr = 0x0000040EUL;
        constexpr const auto name = "ia32_mc3_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc3_misc
    {
        constexpr const auto addr = 0x0000040FUL;
        constexpr const auto name = "ia32_mc3_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc4_ctl
    {
        constexpr const auto addr = 0x00000410UL;
        constexpr const auto name = "ia32_mc4_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc4_status
    {
        constexpr const auto addr = 0x00000411UL;
        constexpr const auto name = "ia32_mc4_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc4_addr
    {
        constexpr const auto addr = 0x00000412UL;
        constexpr const auto name = "ia32_mc4_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc4_misc
    {
        constexpr const auto addr = 0x00000413UL;
        constexpr const auto name = "ia32_mc4_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc5_ctl
    {
        constexpr const auto addr = 0x00000414UL;
        constexpr const auto name = "ia32_mc5_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc5_status
    {
        constexpr const auto addr = 0x00000415UL;
        constexpr const auto name = "ia32_mc5_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc5_addr
    {
        constexpr const auto addr = 0x00000416UL;
        constexpr const auto name = "ia32_mc5_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc5_misc
    {
        constexpr const auto addr = 0x00000417UL;
        constexpr const auto name = "ia32_mc5_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_star
    {
        constexpr const auto addr = 0xC0000081UL;
        constexpr const auto name = "ia32_fs_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_lstar
    {
        constexpr const auto addr = 0xC0000082UL;
        constexpr const auto name = "ia32_lstar";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_fmask
    {
        constexpr const auto addr = 0xC0000084UL;
        constexpr const auto name = "ia32_fmask";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_kernel_gs_base
    {
        constexpr const auto addr = 0xC0000102UL;
        constexpr const auto name = "ia32_kernel_gs_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_tsc_aux
    {
        constexpr const auto addr = 0xC0000103UL;
        constexpr const auto name = "ia32_tsc_aux";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace aux
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "aux";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }
}
}

// *INDENT-ON*

#endif

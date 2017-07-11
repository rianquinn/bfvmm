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

#ifndef MSRS_INTEL_X64_H
#define MSRS_INTEL_X64_H

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfbitmanip.h>

#include <intrinsics/x86/common/msrs_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{
    using field_type = uint32_t;
    using value_type = uint64_t;

    template<typename A> inline auto get(A addr) noexcept
    { return _read_msr(gsl::narrow_cast<field_type>(addr)); }

    template<typename A, class T> void set(A addr, T val) noexcept
    { _write_msr(gsl::narrow_cast<field_type>(addr), val); }


    namespace ia32_monitor_filter_size
    {
        constexpr const auto addr = 0x00000006UL;
        constexpr const auto name = "ia32_monitor_filter_size";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_platform_id
    {
        constexpr const auto addr = 0x00000017UL;
        constexpr const auto name = "ia32_platform_id";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace platform_id
        {
            constexpr const auto mask = 0x001C000000000000ULL;
            constexpr const auto from = 50;
            constexpr const auto name = "platform_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_feature_control
    {
        constexpr const auto addr = 0x0000003AUL;
        constexpr const auto name = "ia32_feature_control";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace lock_bit
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lock_bit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace enable_vmx_inside_smx
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_vmx_inside_smx";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace enable_vmx_outside_smx
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "enable_vmx_outside_smx";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace senter_local_function_enable
        {
            constexpr const auto mask = 0x0000000000007F00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "senter_local_function_enable";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace senter_global_function_enables
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "senter_global_function_enables";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace sgx_launch_control_enable
        {
            constexpr const auto mask = 0x0000000000020000ULL;
            constexpr const auto from = 17;
            constexpr const auto name = "sgx_launch_control_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace sgx_global_enable
        {
            constexpr const auto mask = 0x0000000000040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "sgx_global_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lmce
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "lmce";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_tsc_adjust
    {
        constexpr const auto addr = 0x0000003BUL;
        constexpr const auto name = "ia32_tsc_adjust";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace thread_adjust
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "thread_adjust";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_bios_updt_trig
    {
        constexpr const auto addr = 0x00000079UL;
        constexpr const auto name = "ia32_bios_updt_trig";

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_bios_sign_id
    {
        constexpr const auto addr = 0x0000008BUL;
        constexpr const auto name = "ia32_bios_sign_id";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace bios_sign_id
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "bios_sign_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_sgxlepubkeyhash0
    {
        constexpr const auto addr = 0x0000008CUL;
        constexpr const auto name = "ia32_sgxlepubkeyhash0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_sgxlepubkeyhash1
    {
        constexpr const auto addr = 0x0000008DUL;
        constexpr const auto name = "ia32_sgxlepubkeyhash1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_sgxlepubkeyhash2
    {
        constexpr const auto addr = 0x0000008EUL;
        constexpr const auto name = "ia32_sgxlepubkeyhash2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_sgxlepubkeyhash3
    {
        constexpr const auto addr = 0x0000008FUL;
        constexpr const auto name = "ia32_sgxlepubkeyhash3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_smm_monitor_ctl
    {
        constexpr const auto addr = 0x0000009BUL;
        constexpr const auto name = "ia32_smm_monitor_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace valid
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "valid";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace vmxoff
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "vmxoff";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace mseg_base
        {
            constexpr const auto mask = 0x00000000FFFFF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "mseg_base";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_smbase
    {
        constexpr const auto addr = 0x0000009EUL;
        constexpr const auto name = "ia32_smbase";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_pmc0
    {
        constexpr const auto addr = 0x000000C1UL;
        constexpr const auto name = "ia32_pmc0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc1
    {
        constexpr const auto addr = 0x000000C2UL;
        constexpr const auto name = "ia32_pmc1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc2
    {
        constexpr const auto addr = 0x000000C3UL;
        constexpr const auto name = "ia32_pmc2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc3
    {
        constexpr const auto addr = 0x000000C4UL;
        constexpr const auto name = "ia32_pmc3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc4
    {
        constexpr const auto addr = 0x000000C5UL;
        constexpr const auto name = "ia32_pmc4";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc5
    {
        constexpr const auto addr = 0x000000C6UL;
        constexpr const auto name = "ia32_pmc5";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc6
    {
        constexpr const auto addr = 0x000000C7UL;
        constexpr const auto name = "ia32_pmc6";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pmc7
    {
        constexpr const auto addr = 0x000000C8UL;
        constexpr const auto name = "ia32_pmc7";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_sysenter_cs
    {
        constexpr const auto addr = 0x00000174UL;
        constexpr const auto name = "ia32_sysenter_cs";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
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
        constexpr const auto addr = 0x00000176;
        constexpr const auto name = "ia32_sysenter_eip";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_perfevtsel0
    {
        constexpr const auto addr = 0x00000186;
        constexpr const auto name = "ia32_perfevtsel0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace event_select
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "event_select";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace umask
        {
            constexpr const auto mask = 0x000000000000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "umask";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace usr
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "usr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace os
        {
            constexpr const auto mask = 0x0000000000020000ULL;
            constexpr const auto from = 17;
            constexpr const auto name = "os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace edge
        {
            constexpr const auto mask = 0x0000000000040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "edge";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pc
        {
            constexpr const auto mask = 0x0000000000080000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "pc";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace interrupt
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "interrupt";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace anythread
        {
            constexpr const auto mask = 0x0000000000200000ULL;
            constexpr const auto from = 21;
            constexpr const auto name = "anythread";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en
        {
            constexpr const auto mask = 0x0000000000400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace inv
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "inv";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace cmask
        {
            constexpr const auto mask = 0x00000000FF000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "cmask";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_perfevtsel1
    {
        constexpr const auto addr = 0x00000187;
        constexpr const auto name = "ia32_perfevtsel1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_perfevtsel2
    {
        constexpr const auto addr = 0x00000188;
        constexpr const auto name = "ia32_perfevtsel2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_perfevtsel3
    {
        constexpr const auto addr = 0x00000189;
        constexpr const auto name = "ia32_perfevtsel3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_perf_status
    {
        constexpr const auto addr = 0x00000198;
        constexpr const auto name = "ia32_perf_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace state_value
        {
            constexpr const auto mask = 0x000000000000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "state_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_perf_ctl
    {
        constexpr const auto addr = 0x00000199;
        constexpr const auto name = "ia32_perf_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace state_value
        {
            constexpr const auto mask = 0x000000000000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "state_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace ida_engage
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "ida_engage";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_clock_modulation
    {
        constexpr const auto addr = 0x0000019A;
        constexpr const auto name = "ia32_clock_modulation";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace ext_duty_cycle
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "ext_duty_cycle";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace duty_cycle_values
        {
            constexpr const auto mask = 0x000000000000000EULL;
            constexpr const auto from = 1;
            constexpr const auto name = "duty_cycle_values";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace enable_modulation
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "enable_modulation";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_therm_interrupt
    {
        constexpr const auto addr = 0x0000019B;
        constexpr const auto name = "ia32_therm_interrupt";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace high_temp
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "high_temp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace low_temp
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "low_temp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace prochot
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "prochot";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace forcepr
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "forcepr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace crit_temp
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "crit_temp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace threshold_1_value
        {
            constexpr const auto mask = 0x0000000000007F00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "threshold_1_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace threshold_1_enable
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "threshold_1_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace threshold_2_value
        {
            constexpr const auto mask = 0x00000000007F0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "threshold_2_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace threshold_2_enable
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "threshold_2_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace power_limit
        {
            constexpr const auto mask = 0x0000000001000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "power_limit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_therm_status
    {
        constexpr const auto addr = 0x0000019C;
        constexpr const auto name = "ia32_therm_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace therm_status
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "therm_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace thermal_status_log
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "thermal_status_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace forcepr_event
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "forcepr_event";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace forcepr_log
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "forcepr_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace crit_temp_status
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "crit_temp_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace crit_temp_log
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "crit_temp_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace therm_threshold1_status
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "therm_threshold1_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace therm_threshold1_log
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "therm_threshold1_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace therm_threshold2_status
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "therm_threshold2_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace therm_threshold2_log
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "therm_threshold2_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace power_limit_status
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "power_limit_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace power_limit_log
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "power_limit_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace current_limit_status
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "current_limit_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace current_limit_log
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "current_limit_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace cross_domain_status
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "cross_domain_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace cross_domain_log
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "cross_domain_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace digital_readout
        {
            constexpr const auto mask = 0x00000000007F0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "digital_readout";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace resolution_celcius
        {
            constexpr const auto mask = 0x0000000078000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "resolution_celcius";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace reading_valid
        {
            constexpr const auto mask = 0x0000000080000000ULL;
            constexpr const auto from = 31;
            constexpr const auto name = "reading_valid";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_misc_enable
    {
        constexpr const auto addr = 0x000001A0UL;
        constexpr const auto name = "ia32_misc_enable";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace fast_strings
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "fast_strings";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace auto_therm_control
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "auto_therm_control";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace perf_monitor
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "perf_monitor";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace branch_trace_storage
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "branch_trace_storage";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace processor_sampling
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "processor_sampling";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace intel_speedstep
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "intel_speedstep";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace monitor_fsm
        {
            constexpr const auto mask = 0x0000000000040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "monitor_fsm";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace limit_cpuid_maxval
        {
            constexpr const auto mask = 0x0000000000400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "limit_cpuid_maxval";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace xtpr_message
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "xtpr_message";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace xd_bit
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "xd_bit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_energy_perf_bias
    {
        constexpr const auto addr = 0x000001B0UL;
        constexpr const auto name = "ia32_energy_perf_bias";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace power_policy
        {
            constexpr const auto mask = 0x000000000000000FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "power_policy";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_package_therm_status
    {
        constexpr const auto addr = 0x000001B1UL;
        constexpr const auto name = "ia32_package_therm_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace pkg_therm_status
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "pkg_therm_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_therm_log
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "pkg_therm_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_prochot_event
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "pkg_prochot_event";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_prochot_log
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "pkg_prochot_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_crit_temp_status
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "pkg_crit_temp_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_crit_temp_log
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "pkg_crit_temp_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_therm_thresh1_status
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "pkg_therm_thresh1_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_therm_thresh1_log
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "pkg_therm_thresh1_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_therm_thresh2_status
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "pkg_therm_thresh2_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_therm_thresh2_log
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "pkg_therm_thresh2_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_power_limit_status
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "pkg_power_limit_status";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pkg_power_limit_log
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "pkg_power_limit_log";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_digital_readout
        {
            constexpr const auto mask = 0x00000000007F0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "pkg_digital_readout";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_package_therm_interrupt
    {
        constexpr const auto addr = 0x000001B2UL;
        constexpr const auto name = "ia32_energy_perf_bias";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace pkg_high_temp
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "pkg_high_temp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_low_temp
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "pkg_low_temp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_prochot
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "pkg_prochot";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_overheat
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "pkg_overheat";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_threshold_1_value
        {
            constexpr const auto mask = 0x0000000000007F00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "pkg_threshold_1_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pkg_threshold_1_enable
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "pkg_threshold_1_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_threshold_2_value
        {
            constexpr const auto mask = 0x00000000007F0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "pkg_threshold_2_value";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace pkg_threshold_2_enable
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "pkg_threshold_2_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pkg_power_limit
        {
            constexpr const auto mask = 0x0000000001000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "pkg_power_limit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_debugctl
    {
        constexpr const auto addr = 0x000001D9UL;
        constexpr const auto name = "ia32_debugctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace lbr
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lbr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace btf
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "btf";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace tr
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "tr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace bts
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "bts";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace btint
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "btint";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace bt_off_os
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "bt_off_os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace bt_off_user
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "bt_off_user";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace freeze_lbrs_on_pmi
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "freeze_lbrs_on_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace freeze_perfmon_on_pmi
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "freeze_perfmon_on_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace enable_uncore_pmi
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_uncore_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace freeze_while_smm
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "freeze_while_smm";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace rtm_debug
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "rtm_debug";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFF003CULL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_debugctl enabled flags:" << bfendl;

            if (lbr::get()) {
                bfdebug << "    - " << lbr::name << bfendl;
            }
            if (btf::get()) {
                bfdebug << "    - " << btf::name << bfendl;
            }
            if (tr::get()) {
                bfdebug << "    - " << tr::name << bfendl;
            }
            if (bts::get()) {
                bfdebug << "    - " << bts::name << bfendl;
            }
            if (btint::get()) {
                bfdebug << "    - " << btint::name << bfendl;
            }
            if (bt_off_os::get()) {
                bfdebug << "    - " << bt_off_os::name << bfendl;
            }
            if (bt_off_user::get()) {
                bfdebug << "    - " << bt_off_user::name << bfendl;
            }
            if (freeze_lbrs_on_pmi::get()) {
                bfdebug << "    - " << freeze_lbrs_on_pmi::name << bfendl;
            }
            if (freeze_perfmon_on_pmi::get()) {
                bfdebug << "    - " << freeze_perfmon_on_pmi::name << bfendl;
            }
            if (enable_uncore_pmi::get()) {
                bfdebug << "    - " << enable_uncore_pmi::name << bfendl;
            }
            if (freeze_while_smm::get()) {
                bfdebug << "    - " << freeze_while_smm::name << bfendl;
            }
            if (rtm_debug::get()) {
                bfdebug << "    - " << rtm_debug::name << bfendl;
            }
        }
    }

    namespace ia32_smrr_physbase
    {
        constexpr const auto addr = 0x000001F2UL;
        constexpr const auto name = "ia32_smrr_physbase";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace type
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "type";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace physbase
        {
            constexpr const auto mask = 0x00000000FFFFF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "physbase";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_smrr_physmask
    {
        constexpr const auto addr = 0x000001F3UL;
        constexpr const auto name = "ia32_smrr_physmask";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace valid
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "valid";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace physmask
        {
            constexpr const auto mask = 0x00000000FFFFF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "physmask";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_platform_dca_cap
    {
        constexpr const auto addr = 0x000001F8UL;
        constexpr const auto name = "ia32_platform_dca_cap";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_cpu_dca_cap
    {
        constexpr const auto addr = 0x000001F9UL;
        constexpr const auto name = "ia32_cpu_dca_cap";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_dca_0_cap
    {
        constexpr const auto addr = 0x000001FAUL;
        constexpr const auto name = "ia32_dca_0_cap";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace dca_active
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "dca_active";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace transaction
        {
            constexpr const auto mask = 0x0000000000000006ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "transaction";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace dca_type
        {
            constexpr const auto mask = 0x0000000000000078ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "dca_type";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace dca_queue_size
        {
            constexpr const auto mask = 0x0000000000000780ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "dca_queue_size";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace dca_delay
        {
            constexpr const auto mask = 0x000000000001E000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "dca_delay";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace sw_block
        {
            constexpr const auto mask = 0x0000000001000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "sw_block";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace hw_block
        {
            constexpr const auto mask = 0x0000000004000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "hw_block";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mtrr_physbase0
    {
        constexpr const auto addr = 0x00000200UL;
        constexpr const auto name = "ia32_mtrr_physbase0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask0
    {
        constexpr const auto addr = 0x00000201UL;
        constexpr const auto name = "ia32_mtrr_physmask0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase1
    {
        constexpr const auto addr = 0x00000202UL;
        constexpr const auto name = "ia32_mtrr_physbase1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask1
    {
        constexpr const auto addr = 0x00000203UL;
        constexpr const auto name = "ia32_mtrr_physmask1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase2
    {
        constexpr const auto addr = 0x00000204UL;
        constexpr const auto name = "ia32_mtrr_physbase2";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask2
    {
        constexpr const auto addr = 0x00000205UL;
        constexpr const auto name = "ia32_mtrr_physmask2";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase3
    {
        constexpr const auto addr = 0x00000206UL;
        constexpr const auto name = "ia32_mtrr_physbase3";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask3
    {
        constexpr const auto addr = 0x00000207UL;
        constexpr const auto name = "ia32_mtrr_physmask3";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase4
    {
        constexpr const auto addr = 0x00000208UL;
        constexpr const auto name = "ia32_mtrr_physbase4";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask4
    {
        constexpr const auto addr = 0x00000209UL;
        constexpr const auto name = "ia32_mtrr_physmask4";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase5
    {
        constexpr const auto addr = 0x0000020AUL;
        constexpr const auto name = "ia32_mtrr_physbase5";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask5
    {
        constexpr const auto addr = 0x0000020BUL;
        constexpr const auto name = "ia32_mtrr_physmask5";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase6
    {
        constexpr const auto addr = 0x0000020CUL;
        constexpr const auto name = "ia32_mtrr_physbase6";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask6
    {
        constexpr const auto addr = 0x0000020DUL;
        constexpr const auto name = "ia32_mtrr_physmask6";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase7
    {
        constexpr const auto addr = 0x0000020EUL;
        constexpr const auto name = "ia32_mtrr_physbase7";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask7
    {
        constexpr const auto addr = 0x0000020FUL;
        constexpr const auto name = "ia32_mtrr_physmask7";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase8
    {
        constexpr const auto addr = 0x00000210UL;
        constexpr const auto name = "ia32_mtrr_physbase8";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask8
    {
        constexpr const auto addr = 0x00000211UL;
        constexpr const auto name = "ia32_mtrr_physmask8";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physbase9
    {
        constexpr const auto addr = 0x00000212UL;
        constexpr const auto name = "ia32_mtrr_physbase9";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_physmask9
    {
        constexpr const auto addr = 0x00000213UL;
        constexpr const auto name = "ia32_mtrr_physmask9";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix64k_00000
    {
        constexpr const auto addr = 0x00000250UL;
        constexpr const auto name = "ia32_mtrr_fix64k_00000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix16k_80000
    {
        constexpr const auto addr = 0x00000258UL;
        constexpr const auto name = "ia32_mtrr_fix16k_80000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix16k_A0000
    {
        constexpr const auto addr = 0x00000259UL;
        constexpr const auto name = "ia32_mtrr_fix16k_A0000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_C0000
    {
        constexpr const auto addr = 0x00000268UL;
        constexpr const auto name = "ia32_mtrr_fix4k_C0000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_C8000
    {
        constexpr const auto addr = 0x00000269UL;
        constexpr const auto name = "ia32_mtrr_fix4k_C8000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_D0000
    {
        constexpr const auto addr = 0x0000026AUL;
        constexpr const auto name = "ia32_mtrr_fix4k_D0000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_D8000
    {
        constexpr const auto addr = 0x0000026BUL;
        constexpr const auto name = "ia32_mtrr_fix4k_D8000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_E0000
    {
        constexpr const auto addr = 0x0000026CUL;
        constexpr const auto name = "ia32_mtrr_fix4k_E0000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_E8000
    {
        constexpr const auto addr = 0x0000026DUL;
        constexpr const auto name = "ia32_mtrr_fix4k_E8000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_F0000
    {
        constexpr const auto addr = 0x0000026EUL;
        constexpr const auto name = "ia32_mtrr_fix4k_F0000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mtrr_fix4k_F8000
    {
        constexpr const auto addr = 0x0000026FUL;
        constexpr const auto name = "ia32_mtrr_fix4k_F8000";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc0_ctl2
    {
        constexpr const auto addr = 0x00000280UL;
        constexpr const auto name = "ia32_mc0_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc1_ctl2
    {
        constexpr const auto addr = 0x00000281UL;
        constexpr const auto name = "ia32_mc1_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc2_ctl2
    {
        constexpr const auto addr = 0x00000282UL;
        constexpr const auto name = "ia32_mc2_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc3_ctl2
    {
        constexpr const auto addr = 0x00000283UL;
        constexpr const auto name = "ia32_mc3_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc4_ctl2
    {
        constexpr const auto addr = 0x00000284UL;
        constexpr const auto name = "ia32_mc4_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc5_ctl2
    {
        constexpr const auto addr = 0x00000285UL;
        constexpr const auto name = "ia32_mc5_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc6_ctl2
    {
        constexpr const auto addr = 0x00000286UL;
        constexpr const auto name = "ia32_mc6_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc7_ctl2
    {
        constexpr const auto addr = 0x00000287UL;
        constexpr const auto name = "ia32_mc7_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc8_ctl2
    {
        constexpr const auto addr = 0x00000288UL;
        constexpr const auto name = "ia32_mc8_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc9_ctl2
    {
        constexpr const auto addr = 0x00000289UL;
        constexpr const auto name = "ia32_mc9_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc10_ctl2
    {
        constexpr const auto addr = 0x0000028AUL;
        constexpr const auto name = "ia32_mc10_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc11_ctl2
    {
        constexpr const auto addr = 0x0000028BUL;
        constexpr const auto name = "ia32_mc11_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc12_ctl2
    {
        constexpr const auto addr = 0x0000028CUL;
        constexpr const auto name = "ia32_mc12_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc13_ctl2
    {
        constexpr const auto addr = 0x0000028DUL;
        constexpr const auto name = "ia32_mc13_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc14_ctl2
    {
        constexpr const auto addr = 0x0000028EUL;
        constexpr const auto name = "ia32_mc14_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc15_ctl2
    {
        constexpr const auto addr = 0x0000028FUL;
        constexpr const auto name = "ia32_mc15_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc16_ctl2
    {
        constexpr const auto addr = 0x00000290UL;
        constexpr const auto name = "ia32_mc16_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc17_ctl2
    {
        constexpr const auto addr = 0x00000291UL;
        constexpr const auto name = "ia32_mc17_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc18_ctl2
    {
        constexpr const auto addr = 0x00000292UL;
        constexpr const auto name = "ia32_mc18_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc19_ctl2
    {
        constexpr const auto addr = 0x00000293UL;
        constexpr const auto name = "ia32_mc19_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc20_ctl2
    {
        constexpr const auto addr = 0x00000294UL;
        constexpr const auto name = "ia32_mc20_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc21_ctl2
    {
        constexpr const auto addr = 0x00000295UL;
        constexpr const auto name = "ia32_mc21_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc22_ctl2
    {
        constexpr const auto addr = 0x00000296UL;
        constexpr const auto name = "ia32_mc22_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc23_ctl2
    {
        constexpr const auto addr = 0x00000297UL;
        constexpr const auto name = "ia32_mc23_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc24_ctl2
    {
        constexpr const auto addr = 0x00000298UL;
        constexpr const auto name = "ia32_mc24_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc25_ctl2
    {
        constexpr const auto addr = 0x00000299UL;
        constexpr const auto name = "ia32_mc25_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc26_ctl2
    {
        constexpr const auto addr = 0x0000029AUL;
        constexpr const auto name = "ia32_mc26_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc27_ctl2
    {
        constexpr const auto addr = 0x0000029BUL;
        constexpr const auto name = "ia32_mc27_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc28_ctl2
    {
        constexpr const auto addr = 0x0000029CUL;
        constexpr const auto name = "ia32_mc28_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc29_ctl2
    {
        constexpr const auto addr = 0x0000029DUL;
        constexpr const auto name = "ia32_mc29_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc30_ctl2
    {
        constexpr const auto addr = 0x0000029EUL;
        constexpr const auto name = "ia32_mc30_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc31_ctl2
    {
        constexpr const auto addr = 0x0000029FUL;
        constexpr const auto name = "ia32_mc31_ctl2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace error_threshold
        {
            constexpr const auto mask = 0x0000000000007FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "error_threshold";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cmci_en
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "cmci_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mtrr_def_type
    {
        constexpr const auto addr = 0x000002FFUL;
        constexpr const auto name = "ia32_mtrr_def_type";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace def_mem_type
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "def_mem_type";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace fixed_range_mtrr
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "fixed_range_mtrr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace mtrr
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "mtrr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_fixed_ctr0
    {
        constexpr const auto addr = 0x00000309UL;
        constexpr const auto name = "ia32_fixed_ctr0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_fixed_ctr1
    {
        constexpr const auto addr = 0x0000030AUL;
        constexpr const auto name = "ia32_fixed_ctr1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_fixed_ctr2
    {
        constexpr const auto addr = 0x0000030BUL;
        constexpr const auto name = "ia32_fixed_ctr2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_perf_capabilities
    {
        constexpr const auto addr = 0x00000345UL;
        constexpr const auto name = "ia32_perf_capabilities";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace lbo_format
        {
            constexpr const auto mask = 0x000000000000003FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lbo_format";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace pebs_trap
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "pebs_trap";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pebs_savearchregs
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "pebs_savearchregs";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pebs_record_format
        {
            constexpr const auto mask = 0x0000000000000F00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "pebs_record_format";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace freeze
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "freeze";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace counter_width
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "counter_width";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_fixed_ctr_ctrl
    {
        constexpr const auto addr = 0x0000038DUL;
        constexpr const auto name = "ia32_fixed_ctr_ctrl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace en0_os
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "en0_os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en0_usr
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "en0_usr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en0_anythread
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "en0_anythread";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en0_pmi
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "en0_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en1_os
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "en1_os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en1_usr
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "en1_usr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en1_anythread
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "en1_anythread";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en1_pmi
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "en1_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en2_os
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "en2_os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en2_usr
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "en2_usr";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en2_anythread
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "en2_anythread";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace en2_pmi
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "en2_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_perf_global_status
    {
        constexpr const auto addr = 0x0000038EUL;
        constexpr const auto name = "ia32_perf_global_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace ovf_pmc0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "ovf_pmc0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_pmc1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "ovf_pmc1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_pmc2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "ovf_pmc2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_pmc3
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "ovf_pmc3";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixedctr0
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "ovf_fixedctr0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixedctr1
        {
            constexpr const auto mask = 0x0000000200000000ULL;
            constexpr const auto from = 33;
            constexpr const auto name = "ovf_fixedctr1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixedctr2
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "ovf_fixedctr2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace trace_topa_pmi
        {
            constexpr const auto mask = 0x0080000000000000ULL;
            constexpr const auto from = 55;
            constexpr const auto name = "trace_topa_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lbr_frz
        {
            constexpr const auto mask = 0x0400000000000000ULL;
            constexpr const auto from = 58;
            constexpr const auto name = "lbr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ctr_frz
        {
            constexpr const auto mask = 0x0800000000000000ULL;
            constexpr const auto from = 59;
            constexpr const auto name = "ctr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace asci
        {
            constexpr const auto mask = 0x1000000000000000ULL;
            constexpr const auto from = 60;
            constexpr const auto name = "asci";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_uncore
        {
            constexpr const auto mask = 0x2000000000000000ULL;
            constexpr const auto from = 61;
            constexpr const auto name = "ovf_uncore";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovfbuf
        {
            constexpr const auto mask = 0x4000000000000000ULL;
            constexpr const auto from = 62;
            constexpr const auto name = "ovfbuf";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace condchgd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63;
            constexpr const auto name = "condchgd";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_perf_global_ctrl
    {
        constexpr const auto addr = 0x0000038FUL;
        constexpr const auto name = "ia32_perf_global_ctrl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace pmc0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "pmc0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "pmc1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "pmc2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc3
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "pmc3";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc4
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "pmc4";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc5
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "pmc5";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc6
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "pmc6";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace pmc7
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "pmc7";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "fixed_ctr0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000ULL;
            constexpr const auto from = 33;
            constexpr const auto name = "fixed_ctr1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "fixed_ctr2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_perf_global_ctrl enabled flags:" << bfendl;

            if (pmc0::get()) {
                bfdebug << "    - " << pmc0::name << bfendl;
            }
            if (pmc1::get()) {
                bfdebug << "    - " << pmc1::name << bfendl;
            }
            if (pmc2::get()) {
                bfdebug << "    - " << pmc2::name << bfendl;
            }
            if (pmc3::get()) {
                bfdebug << "    - " << pmc3::name << bfendl;
            }
            if (pmc4::get()) {
                bfdebug << "    - " << pmc4::name << bfendl;
            }
            if (pmc5::get()) {
                bfdebug << "    - " << pmc5::name << bfendl;
            }
            if (pmc6::get()) {
                bfdebug << "    - " << pmc6::name << bfendl;
            }
            if (pmc7::get()) {
                bfdebug << "    - " << pmc7::name << bfendl;
            }
            if (fixed_ctr0::get()) {
                bfdebug << "    - " << fixed_ctr0::name << bfendl;
            }
            if (fixed_ctr1::get()) {
                bfdebug << "    - " << fixed_ctr1::name << bfendl;
            }
            if (fixed_ctr2::get()) {
                bfdebug << "    - " << fixed_ctr2::name << bfendl;
            }
        }
    }

    namespace ia32_perf_global_ovf_ctrl
    {
        constexpr const auto addr = 0x00000390UL;
        constexpr const auto name = "ia32_perf_global_ovf_ctrl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace clear_ovf_pmc0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "clear_ovf_pmc0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_pmc1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "clear_ovf_pmc1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_pmc2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "clear_ovf_pmc2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "clear_ovf_fixed_ctr0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000ULL;
            constexpr const auto from = 33;
            constexpr const auto name = "clear_ovf_fixed_ctr1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "clear_ovf_fixed_ctr2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_trace_topa_pmi
        {
            constexpr const auto mask = 0x0080000000000000ULL;
            constexpr const auto from = 55;
            constexpr const auto name = "clear_trace_topa_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lbr_frz
        {
            constexpr const auto mask = 0x0400000000000000ULL;
            constexpr const auto from = 58;
            constexpr const auto name = "lbr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ctr_frz
        {
            constexpr const auto mask = 0x0800000000000000ULL;
            constexpr const auto from = 59;
            constexpr const auto name = "ctr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovf_uncore
        {
            constexpr const auto mask = 0x2000000000000000ULL;
            constexpr const auto from = 61;
            constexpr const auto name = "clear_ovf_uncore";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_ovfbuf
        {
            constexpr const auto mask = 0x4000000000000000ULL;
            constexpr const auto from = 62;
            constexpr const auto name = "clear_ovfbuf";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace clear_condchgd
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63;
            constexpr const auto name = "clear_condchgd";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_perf_global_status_set
    {
        constexpr const auto addr = 0x00000391UL;
        constexpr const auto name = "ia32_perf_global_status_set";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace ovf_pmc0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "ovf_pmc0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_pmc1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "ovf_pmc1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_pmc2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "ovf_pmc2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "ovf_fixed_ctr0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000ULL;
            constexpr const auto from = 33;
            constexpr const auto name = "ovf_fixed_ctr1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "ovf_fixed_ctr2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace trace_topa_pmi
        {
            constexpr const auto mask = 0x0080000000000000ULL;
            constexpr const auto from = 55;
            constexpr const auto name = "trace_topa_pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lbr_frz
        {
            constexpr const auto mask = 0x0400000000000000ULL;
            constexpr const auto from = 58;
            constexpr const auto name = "lbr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ctr_frz
        {
            constexpr const auto mask = 0x0800000000000000ULL;
            constexpr const auto from = 59;
            constexpr const auto name = "ctr_frz";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovf_uncore
        {
            constexpr const auto mask = 0x2000000000000000ULL;
            constexpr const auto from = 61;
            constexpr const auto name = "ovf_uncore";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace ovfbuf
        {
            constexpr const auto mask = 0x4000000000000000ULL;
            constexpr const auto from = 62;
            constexpr const auto name = "clear_ovfbuf";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_perf_global_inuse
    {
        constexpr const auto addr = 0x00000392UL;
        constexpr const auto name = "ia32_perf_global_inuse";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace perfevtsel0
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "perfevtsel0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace perfevtsel1
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "perfevtsel1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace perfevtsel2
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "perfevtsel2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace fixed_ctr0
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "fixed_ctr0";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace fixed_ctr1
        {
            constexpr const auto mask = 0x0000000200000000ULL;
            constexpr const auto from = 33;
            constexpr const auto name = "fixed_ctr1";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace fixed_ctr2
        {
            constexpr const auto mask = 0x0000000400000000ULL;
            constexpr const auto from = 34;
            constexpr const auto name = "fixed_ctr2";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pmi
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63;
            constexpr const auto name = "pmi";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_pebs_enable
    {
        constexpr const auto addr = 0x000003F1UL;
        constexpr const auto name = "ia32_pebs_enable";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace pebs
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "pebs";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_mc6_ctl
    {
        constexpr const auto addr = 0x00000418UL;
        constexpr const auto name = "ia32_mc6_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc6_status
    {
        constexpr const auto addr = 0x00000419UL;
        constexpr const auto name = "ia32_mc6_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc6_addr
    {
        constexpr const auto addr = 0x0000041AUL;
        constexpr const auto name = "ia32_mc6_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc6_misc
    {
        constexpr const auto addr = 0x0000041BUL;
        constexpr const auto name = "ia32_mc6_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc7_ctl
    {
        constexpr const auto addr = 0x0000041CUL;
        constexpr const auto name = "ia32_mc7_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc7_status
    {
        constexpr const auto addr = 0x0000041DUL;
        constexpr const auto name = "ia32_mc7_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc7_addr
    {
        constexpr const auto addr = 0x0000041EUL;
        constexpr const auto name = "ia32_mc7_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc7_misc
    {
        constexpr const auto addr = 0x0000041FUL;
        constexpr const auto name = "ia32_mc7_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc8_ctl
    {
        constexpr const auto addr = 0x00000420UL;
        constexpr const auto name = "ia32_mc8_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc8_status
    {
        constexpr const auto addr = 0x00000421UL;
        constexpr const auto name = "ia32_mc8_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc8_addr
    {
        constexpr const auto addr = 0x00000422UL;
        constexpr const auto name = "ia32_mc8_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc8_misc
    {
        constexpr const auto addr = 0x00000423UL;
        constexpr const auto name = "ia32_mc8_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc9_ctl
    {
        constexpr const auto addr = 0x00000424UL;
        constexpr const auto name = "ia32_mc9_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc9_status
    {
        constexpr const auto addr = 0x00000425UL;
        constexpr const auto name = "ia32_mc9_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc9_addr
    {
        constexpr const auto addr = 0x00000426UL;
        constexpr const auto name = "ia32_mc9_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc9_misc
    {
        constexpr const auto addr = 0x00000427UL;
        constexpr const auto name = "ia32_mc9_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc10_ctl
    {
        constexpr const auto addr = 0x00000428UL;
        constexpr const auto name = "ia32_mc10_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc10_status
    {
        constexpr const auto addr = 0x00000429UL;
        constexpr const auto name = "ia32_mc10_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc10_addr
    {
        constexpr const auto addr = 0x0000042AUL;
        constexpr const auto name = "ia32_mc10_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc10_misc
    {
        constexpr const auto addr = 0x0000042BUL;
        constexpr const auto name = "ia32_mc10_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc11_ctl
    {
        constexpr const auto addr = 0x0000042CUL;
        constexpr const auto name = "ia32_mc11_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc11_status
    {
        constexpr const auto addr = 0x0000042DUL;
        constexpr const auto name = "ia32_mc11_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc11_addr
    {
        constexpr const auto addr = 0x0000042EUL;
        constexpr const auto name = "ia32_mc11_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc11_misc
    {
        constexpr const auto addr = 0x0000042FUL;
        constexpr const auto name = "ia32_mc11_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc12_ctl
    {
        constexpr const auto addr = 0x00000430UL;
        constexpr const auto name = "ia32_mc12_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc12_status
    {
        constexpr const auto addr = 0x00000431UL;
        constexpr const auto name = "ia32_mc12_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc12_addr
    {
        constexpr const auto addr = 0x00000432UL;
        constexpr const auto name = "ia32_mc12_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc12_misc
    {
        constexpr const auto addr = 0x00000433UL;
        constexpr const auto name = "ia32_mc12_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc13_ctl
    {
        constexpr const auto addr = 0x00000434UL;
        constexpr const auto name = "ia32_mc13_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc13_status
    {
        constexpr const auto addr = 0x00000435UL;
        constexpr const auto name = "ia32_mc13_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc13_addr
    {
        constexpr const auto addr = 0x00000436UL;
        constexpr const auto name = "ia32_mc13_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc13_misc
    {
        constexpr const auto addr = 0x00000437UL;
        constexpr const auto name = "ia32_mc13_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc14_ctl
    {
        constexpr const auto addr = 0x00000438UL;
        constexpr const auto name = "ia32_mc14_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc14_status
    {
        constexpr const auto addr = 0x00000439UL;
        constexpr const auto name = "ia32_mc14_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc14_addr
    {
        constexpr const auto addr = 0x0000043AUL;
        constexpr const auto name = "ia32_mc14_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc14_misc
    {
        constexpr const auto addr = 0x0000043BUL;
        constexpr const auto name = "ia32_mc14_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc15_ctl
    {
        constexpr const auto addr = 0x0000043CUL;
        constexpr const auto name = "ia32_mc15_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc15_status
    {
        constexpr const auto addr = 0x0000043DUL;
        constexpr const auto name = "ia32_mc15_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc15_addr
    {
        constexpr const auto addr = 0x0000043EUL;
        constexpr const auto name = "ia32_mc15_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc15_misc
    {
        constexpr const auto addr = 0x0000043FUL;
        constexpr const auto name = "ia32_mc15_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc16_ctl
    {
        constexpr const auto addr = 0x00000440UL;
        constexpr const auto name = "ia32_mc16_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc16_status
    {
        constexpr const auto addr = 0x00000441UL;
        constexpr const auto name = "ia32_mc16_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc16_addr
    {
        constexpr const auto addr = 0x00000442UL;
        constexpr const auto name = "ia32_mc16_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc16_misc
    {
        constexpr const auto addr = 0x00000443UL;
        constexpr const auto name = "ia32_mc16_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc17_ctl
    {
        constexpr const auto addr = 0x00000444UL;
        constexpr const auto name = "ia32_mc17_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc17_status
    {
        constexpr const auto addr = 0x00000445UL;
        constexpr const auto name = "ia32_mc17_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc17_addr
    {
        constexpr const auto addr = 0x00000446UL;
        constexpr const auto name = "ia32_mc17_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc17_misc
    {
        constexpr const auto addr = 0x00000447UL;
        constexpr const auto name = "ia32_mc17_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc18_ctl
    {
        constexpr const auto addr = 0x00000448UL;
        constexpr const auto name = "ia32_mc18_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc18_status
    {
        constexpr const auto addr = 0x00000449UL;
        constexpr const auto name = "ia32_mc18_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc18_addr
    {
        constexpr const auto addr = 0x0000044AUL;
        constexpr const auto name = "ia32_mc18_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc18_misc
    {
        constexpr const auto addr = 0x0000044BUL;
        constexpr const auto name = "ia32_mc18_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc19_ctl
    {
        constexpr const auto addr = 0x0000044CUL;
        constexpr const auto name = "ia32_mc19_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc19_status
    {
        constexpr const auto addr = 0x0000044DUL;
        constexpr const auto name = "ia32_mc19_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc19_addr
    {
        constexpr const auto addr = 0x0000044EUL;
        constexpr const auto name = "ia32_mc19_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc19_misc
    {
        constexpr const auto addr = 0x0000044FUL;
        constexpr const auto name = "ia32_mc19_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc20_ctl
    {
        constexpr const auto addr = 0x00000450UL;
        constexpr const auto name = "ia32_mc20_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc20_status
    {
        constexpr const auto addr = 0x00000451UL;
        constexpr const auto name = "ia32_mc20_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc20_addr
    {
        constexpr const auto addr = 0x00000452UL;
        constexpr const auto name = "ia32_mc20_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc20_misc
    {
        constexpr const auto addr = 0x00000453UL;
        constexpr const auto name = "ia32_mc20_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc21_ctl
    {
        constexpr const auto addr = 0x00000454UL;
        constexpr const auto name = "ia32_mc21_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc21_status
    {
        constexpr const auto addr = 0x00000455UL;
        constexpr const auto name = "ia32_mc21_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc21_addr
    {
        constexpr const auto addr = 0x00000456UL;
        constexpr const auto name = "ia32_mc21_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc21_misc
    {
        constexpr const auto addr = 0x00000457UL;
        constexpr const auto name = "ia32_mc21_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc22_ctl
    {
        constexpr const auto addr = 0x00000458UL;
        constexpr const auto name = "ia32_mc22_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc22_status
    {
        constexpr const auto addr = 0x00000459UL;
        constexpr const auto name = "ia32_mc22_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc22_addr
    {
        constexpr const auto addr = 0x0000045AUL;
        constexpr const auto name = "ia32_mc22_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc22_misc
    {
        constexpr const auto addr = 0x0000045BUL;
        constexpr const auto name = "ia32_mc22_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc23_ctl
    {
        constexpr const auto addr = 0x0000045CUL;
        constexpr const auto name = "ia32_mc23_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc23_status
    {
        constexpr const auto addr = 0x0000045DUL;
        constexpr const auto name = "ia32_mc23_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc23_addr
    {
        constexpr const auto addr = 0x0000045EUL;
        constexpr const auto name = "ia32_mc23_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc23_misc
    {
        constexpr const auto addr = 0x0000045FUL;
        constexpr const auto name = "ia32_mc23_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc24_ctl
    {
        constexpr const auto addr = 0x00000460UL;
        constexpr const auto name = "ia32_mc24_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc24_status
    {
        constexpr const auto addr = 0x00000461UL;
        constexpr const auto name = "ia32_mc24_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc24_addr
    {
        constexpr const auto addr = 0x00000462UL;
        constexpr const auto name = "ia32_mc24_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc24_misc
    {
        constexpr const auto addr = 0x00000463UL;
        constexpr const auto name = "ia32_mc24_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc25_ctl
    {
        constexpr const auto addr = 0x00000464UL;
        constexpr const auto name = "ia32_mc25_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc25_status
    {
        constexpr const auto addr = 0x00000465UL;
        constexpr const auto name = "ia32_mc25_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc25_addr
    {
        constexpr const auto addr = 0x00000466UL;
        constexpr const auto name = "ia32_mc25_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc25_misc
    {
        constexpr const auto addr = 0x00000467UL;
        constexpr const auto name = "ia32_mc25_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc26_ctl
    {
        constexpr const auto addr = 0x00000468UL;
        constexpr const auto name = "ia32_mc26_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc26_status
    {
        constexpr const auto addr = 0x00000469UL;
        constexpr const auto name = "ia32_mc26_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc26_addr
    {
        constexpr const auto addr = 0x0000046AUL;
        constexpr const auto name = "ia32_mc26_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc26_misc
    {
        constexpr const auto addr = 0x0000046BUL;
        constexpr const auto name = "ia32_mc26_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc27_ctl
    {
        constexpr const auto addr = 0x0000046CUL;
        constexpr const auto name = "ia32_mc27_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc27_status
    {
        constexpr const auto addr = 0x0000046DUL;
        constexpr const auto name = "ia32_mc27_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc27_addr
    {
        constexpr const auto addr = 0x0000046EUL;
        constexpr const auto name = "ia32_mc27_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc27_misc
    {
        constexpr const auto addr = 0x0000046FUL;
        constexpr const auto name = "ia32_mc27_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc28_ctl
    {
        constexpr const auto addr = 0x00000470UL;
        constexpr const auto name = "ia32_mc28_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc28_status
    {
        constexpr const auto addr = 0x00000471UL;
        constexpr const auto name = "ia32_mc28_status";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc28_addr
    {
        constexpr const auto addr = 0x00000472UL;
        constexpr const auto name = "ia32_mc28_addr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_mc28_misc
    {
        constexpr const auto addr = 0x00000473UL;
        constexpr const auto name = "ia32_mc28_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_vmx_basic
    {
        constexpr const auto addr = 0x00000480UL;
        constexpr const auto name = "ia32_vmx_basic";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace revision_id
        {
            constexpr const auto mask = 0x000000007FFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "revision_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace vmxon_vmcs_region_size
        {
            constexpr const auto mask = 0x00001FFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "vmxon_vmcs_region_size";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace physical_address_width
        {
            constexpr const auto mask = 0x0001000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "physical_address_width";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace dual_monitor_mode_support
        {
            constexpr const auto mask = 0x0002000000000000ULL;
            constexpr const auto from = 49;
            constexpr const auto name = "dual_monitor_mode_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace memory_type
        {
            constexpr const auto mask = 0x003C000000000000ULL;
            constexpr const auto from = 50;
            constexpr const auto name = "memory_type";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace ins_outs_exit_information
        {
            constexpr const auto mask = 0x0040000000000000ULL;
            constexpr const auto from = 54;
            constexpr const auto name = "ins_outs_exit_information";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace true_based_controls
        {
            constexpr const auto mask = 0x0080000000000000ULL;
            constexpr const auto from = 55;
            constexpr const auto name = "true_based_controls";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_basic enabled flags:" << bfendl;

            if (physical_address_width::get()) {
                bfdebug << "    - " << physical_address_width::name << bfendl;
            }
            if (dual_monitor_mode_support::get()) {
                bfdebug << "    - " << dual_monitor_mode_support::name << bfendl;
            }
            if (ins_outs_exit_information::get()) {
                bfdebug << "    - " << ins_outs_exit_information::name << bfendl;
            }
            if (true_based_controls::get()) {
                bfdebug << "    - " << true_based_controls::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_basic fields:" << bfendl;

            bfdebug << "    - " << revision_id::name << " = "
                    << view_as_pointer(revision_id::get()) << bfendl;
            bfdebug << "    - " << vmxon_vmcs_region_size::name << " = "
                    << view_as_pointer(vmxon_vmcs_region_size::get()) << bfendl;
            bfdebug << "    - " << memory_type::name << " = "
                    << view_as_pointer(memory_type::get()) << bfendl;
        }
    }

    namespace ia32_vmx_pinbased_ctls
    {
        constexpr const auto addr = 0x00000481UL;
        constexpr const auto name = "ia32_vmx_pinbased_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace allowed_0_settings
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "allowed_0_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace allowed_1_settings
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "allowed_1_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_vmx_procbased_ctls
    {
        constexpr const auto addr = 0x00000482UL;
        constexpr const auto name = "ia32_vmx_procbased_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace allowed_0_settings
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "allowed_0_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace allowed_1_settings
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "allowed_1_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_vmx_exit_ctls
    {
        constexpr const auto addr = 0x00000483UL;
        constexpr const auto name = "ia32_vmx_exit_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace allowed_0_settings
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "allowed_0_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace allowed_1_settings
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "allowed_1_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_vmx_entry_ctls
    {
        constexpr const auto addr = 0x00000484UL;
        constexpr const auto name = "ia32_vmx_entry_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace allowed_0_settings
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "allowed_0_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace allowed_1_settings
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "allowed_1_settings";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_vmx_misc
    {
        constexpr const auto addr = 0x00000485UL;
        constexpr const auto name = "ia32_vmx_misc";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace preemption_timer_decrement
        {
            constexpr const auto mask = 0x000000000000001FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "preemption_timer_decrement";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace store_efer_lma_on_vm_exit
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "store_efer_lma_on_vm_exit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace activity_state_hlt_support
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "activity_state_hlt_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace activity_state_shutdown_support
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "activity_state_shutdown_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace activity_state_wait_for_sipi_support
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "activity_state_wait_for_sipi_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace processor_trace_support
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "processor_trace_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace rdmsr_in_smm_support
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "rdmsr_in_smm_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace cr3_targets
        {
            constexpr const auto mask = 0x0000000001FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_targets";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace max_num_msr_load_store_on_exit
        {
            constexpr const auto mask = 0x000000000E000000ULL;
            constexpr const auto from = 25;
            constexpr const auto name = "max_num_msr_load_store_on_exit";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace vmxoff_blocked_smi_support
        {
            constexpr const auto mask = 0x0000000010000000ULL;
            constexpr const auto from = 28;
            constexpr const auto name = "vmxoff_blocked_smi_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace vmwrite_all_fields_support
        {
            constexpr const auto mask = 0x0000000020000000ULL;
            constexpr const auto from = 29;
            constexpr const auto name = "vmwrite_all_fields_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace injection_with_instruction_length_of_zero
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "injection_with_instruction_length_of_zero";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_misc enabled flags:" << bfendl;

            if (store_efer_lma_on_vm_exit::get()) {
                bfdebug << "    - " << store_efer_lma_on_vm_exit::name << bfendl;
            }
            if (activity_state_hlt_support::get()) {
                bfdebug << "    - " << activity_state_hlt_support::name << bfendl;
            }
            if (activity_state_shutdown_support::get()) {
                bfdebug << "    - " << activity_state_shutdown_support::name << bfendl;
            }
            if (activity_state_wait_for_sipi_support::get()) {
                bfdebug << "    - " << activity_state_wait_for_sipi_support::name << bfendl;
            }
            if (processor_trace_support::get()) {
                bfdebug << "    - " << processor_trace_support::name << bfendl;
            }
            if (rdmsr_in_smm_support::get()) {
                bfdebug << "    - " << rdmsr_in_smm_support::name << bfendl;
            }
            if (vmxoff_blocked_smi_support::get()) {
                bfdebug << "    - " << vmxoff_blocked_smi_support::name << bfendl;
            }
            if (vmwrite_all_fields_support::get()) {
                bfdebug << "    - " << vmwrite_all_fields_support::name << bfendl;
            }
            if (injection_with_instruction_length_of_zero::get()) {
                bfdebug << "    - " << injection_with_instruction_length_of_zero::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_misc fields:" << bfendl;

            bfdebug << "    - " << preemption_timer_decrement::name << " = "
                    << view_as_pointer(preemption_timer_decrement::get()) << bfendl;
            bfdebug << "    - " << cr3_targets::name << " = "
                    << view_as_pointer(cr3_targets::get()) << bfendl;
            bfdebug << "    - " << max_num_msr_load_store_on_exit::name << " = "
                    << view_as_pointer(max_num_msr_load_store_on_exit::get()) << bfendl;
        }
    }

    namespace ia32_vmx_cr0_fixed0
    {
        constexpr const auto addr = 0x00000486UL;
        constexpr const auto name = "ia32_vmx_cr0_fixed0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_vmx_cr0_fixed1
    {
        constexpr const auto addr = 0x00000487UL;
        constexpr const auto name = "ia32_vmx_cr0_fixed1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_vmx_cr4_fixed0
    {
        constexpr const auto addr = 0x00000488UL;
        constexpr const auto name = "ia32_vmx_cr4_fixed0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_vmx_cr4_fixed1
    {
        constexpr const auto addr = 0x00000489UL;
        constexpr const auto name = "ia32_vmx_cr4_fixed1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_vmx_vmcs_enum
    {
        constexpr const auto addr = 0x0000048AUL;
        constexpr const auto name = "ia32_vmx_vmcs_enum";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace highest_index
        {
            constexpr const auto mask = 0x00000000000003FEULL;
            constexpr const auto from = 1;
            constexpr const auto name = "highest_index";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_vmx_procbased_ctls2
    {
        constexpr const auto addr = 0x0000048BUL;
        constexpr const auto name = "ia32_vmx_procbased_ctls2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline auto allowed0()
        { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

        inline auto allowed1()
        { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

        namespace virtualize_apic_accesses
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtualize_apic_accesses";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_ept
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "enable_ept";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace descriptor_table_exiting
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "descriptor_table_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_rdtscp
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "enable_rdtscp";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtualize_x2apic_mode
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "virtualize_x2apic_mode";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_vpid
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "enable_vpid";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace wbinvd_exiting
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "wbinvd_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace unrestricted_guest
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "unrestricted_guest";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace apic_register_virtualization
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "apic_register_virtualization";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtual_interrupt_delivery
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "virtual_interrupt_delivery";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace pause_loop_exiting
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "pause_loop_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdrand_exiting
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdrand_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_invpcid
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "enable_invpcid";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_vm_functions
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "enable_vm_functions";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace vmcs_shadowing
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "vmcs_shadowing";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_encls_exiting
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "enable_encls_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdseed_exiting
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "rdseed_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_pml
        {
            constexpr const auto mask = 0x0000000000020000ULL;
            constexpr const auto from = 17;
            constexpr const auto name = "enable_pml";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace ept_violation_ve
        {
            constexpr const auto mask = 0x0000000000040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "ept_violation_ve";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace pt_conceal_nonroot_operation
        {
            constexpr const auto mask = 0x0000000000080000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "pt_conceal_nonroot_operation";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace enable_xsaves_xrstors
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "enable_xsaves_xrstors";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace ept_mode_based_control
        {
            constexpr const auto mask = 0x0000000000400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "ept_mode_based_control";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_tsc_scaling
        {
            constexpr const auto mask = 0x0000000002000000ULL;
            constexpr const auto from = 25;
            constexpr const auto name = "use_tsc_scaling";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 enabled flags:" << bfendl;

            if (virtualize_apic_accesses::get()) {
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            }
            if (enable_ept::get()) {
                bfdebug << "    - " << enable_ept::name << bfendl;
            }
            if (descriptor_table_exiting::get()) {
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            }
            if (enable_rdtscp::get()) {
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            }
            if (virtualize_x2apic_mode::get()) {
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            }
            if (enable_vpid::get()) {
                bfdebug << "    - " << enable_vpid::name << bfendl;
            }
            if (wbinvd_exiting::get()) {
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            }
            if (unrestricted_guest::get()) {
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            }
            if (apic_register_virtualization::get()) {
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            }
            if (virtual_interrupt_delivery::get()) {
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            }
            if (pause_loop_exiting::get()) {
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            }
            if (rdrand_exiting::get()) {
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            }
            if (enable_invpcid::get()) {
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            }
            if (enable_vm_functions::get()) {
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            }
            if (vmcs_shadowing::get()) {
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            }
            if (enable_encls_exiting::get()) {
                bfdebug << "    - " << enable_encls_exiting::name << bfendl;
            }
            if (rdseed_exiting::get()) {
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            }
            if (enable_pml::get()) {
                bfdebug << "    - " << enable_pml::name << bfendl;
            }
            if (ept_violation_ve::get()) {
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            }
            if (pt_conceal_nonroot_operation::get()) {
                bfdebug << "    - " << pt_conceal_nonroot_operation::name << bfendl;
            }
            if (enable_xsaves_xrstors::get()) {
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;
            }
            if (ept_mode_based_control::get()) {
                bfdebug << "    - " << ept_mode_based_control::name << bfendl;
            }
            if (use_tsc_scaling::get()) {
                bfdebug << "    - " << use_tsc_scaling::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 allowed0 fields:" << bfendl;

            if (virtualize_apic_accesses::is_allowed0()) {
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            }
            if (enable_ept::is_allowed0()) {
                bfdebug << "    - " << enable_ept::name << bfendl;
            }
            if (descriptor_table_exiting::is_allowed0()) {
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            }
            if (enable_rdtscp::is_allowed0()) {
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            }
            if (virtualize_x2apic_mode::is_allowed0()) {
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            }
            if (enable_vpid::is_allowed0()) {
                bfdebug << "    - " << enable_vpid::name << bfendl;
            }
            if (wbinvd_exiting::is_allowed0()) {
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            }
            if (unrestricted_guest::is_allowed0()) {
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            }
            if (apic_register_virtualization::is_allowed0()) {
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            }
            if (virtual_interrupt_delivery::is_allowed0()) {
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            }
            if (pause_loop_exiting::is_allowed0()) {
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            }
            if (rdrand_exiting::is_allowed0()) {
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            }
            if (enable_invpcid::is_allowed0()) {
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            }
            if (enable_vm_functions::is_allowed0()) {
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            }
            if (vmcs_shadowing::is_allowed0()) {
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            }
            if (enable_encls_exiting::is_allowed0()) {
                bfdebug << "    - " << enable_encls_exiting::name << bfendl;
            }
            if (rdseed_exiting::is_allowed0()) {
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            }
            if (enable_pml::is_allowed0()) {
                bfdebug << "    - " << enable_pml::name << bfendl;
            }
            if (ept_violation_ve::is_allowed0()) {
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            }
            if (pt_conceal_nonroot_operation::is_allowed0()) {
                bfdebug << "    - " << pt_conceal_nonroot_operation::name << bfendl;
            }
            if (enable_xsaves_xrstors::is_allowed0()) {
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;
            }
            if (ept_mode_based_control::is_allowed0()) {
                bfdebug << "    - " << ept_mode_based_control::name << bfendl;
            }
            if (use_tsc_scaling::is_allowed0()) {
                bfdebug << "    - " << use_tsc_scaling::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_procbased_ctls2 allowed1 fields:" << bfendl;

            if (virtualize_apic_accesses::is_allowed1()) {
                bfdebug << "    - " << virtualize_apic_accesses::name << bfendl;
            }
            if (enable_ept::is_allowed1()) {
                bfdebug << "    - " << enable_ept::name << bfendl;
            }
            if (descriptor_table_exiting::is_allowed1()) {
                bfdebug << "    - " << descriptor_table_exiting::name << bfendl;
            }
            if (enable_rdtscp::is_allowed1()) {
                bfdebug << "    - " << enable_rdtscp::name << bfendl;
            }
            if (virtualize_x2apic_mode::is_allowed1()) {
                bfdebug << "    - " << virtualize_x2apic_mode::name << bfendl;
            }
            if (enable_vpid::is_allowed1()) {
                bfdebug << "    - " << enable_vpid::name << bfendl;
            }
            if (wbinvd_exiting::is_allowed1()) {
                bfdebug << "    - " << wbinvd_exiting::name << bfendl;
            }
            if (unrestricted_guest::is_allowed1()) {
                bfdebug << "    - " << unrestricted_guest::name << bfendl;
            }
            if (apic_register_virtualization::is_allowed1()) {
                bfdebug << "    - " << apic_register_virtualization::name << bfendl;
            }
            if (virtual_interrupt_delivery::is_allowed1()) {
                bfdebug << "    - " << virtual_interrupt_delivery::name << bfendl;
            }
            if (pause_loop_exiting::is_allowed1()) {
                bfdebug << "    - " << pause_loop_exiting::name << bfendl;
            }
            if (rdrand_exiting::is_allowed1()) {
                bfdebug << "    - " << rdrand_exiting::name << bfendl;
            }
            if (enable_invpcid::is_allowed1()) {
                bfdebug << "    - " << enable_invpcid::name << bfendl;
            }
            if (enable_vm_functions::is_allowed1()) {
                bfdebug << "    - " << enable_vm_functions::name << bfendl;
            }
            if (vmcs_shadowing::is_allowed1()) {
                bfdebug << "    - " << vmcs_shadowing::name << bfendl;
            }
            if (enable_encls_exiting::is_allowed1()) {
                bfdebug << "    - " << enable_encls_exiting::name << bfendl;
            }
            if (rdseed_exiting::is_allowed1()) {
                bfdebug << "    - " << rdseed_exiting::name << bfendl;
            }
            if (enable_pml::is_allowed1()) {
                bfdebug << "    - " << enable_pml::name << bfendl;
            }
            if (ept_violation_ve::is_allowed1()) {
                bfdebug << "    - " << ept_violation_ve::name << bfendl;
            }
            if (pt_conceal_nonroot_operation::is_allowed1()) {
                bfdebug << "    - " << pt_conceal_nonroot_operation::name << bfendl;
            }
            if (enable_xsaves_xrstors::is_allowed1()) {
                bfdebug << "    - " << enable_xsaves_xrstors::name << bfendl;
            }
            if (ept_mode_based_control::is_allowed1()) {
                bfdebug << "    - " << ept_mode_based_control::name << bfendl;
            }
            if (use_tsc_scaling::is_allowed1()) {
                bfdebug << "    - " << use_tsc_scaling::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_ept_vpid_cap
    {
        constexpr const auto addr = 0x0000048CUL;
        constexpr const auto name = "ia32_vmx_ept_vpid_cap";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace execute_only_translation
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "execute_only_translation";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace page_walk_length_of_4
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "page_walk_length_of_4";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace memory_type_uncacheable_supported
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type_uncacheable_supported";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace memory_type_write_back_supported
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "memory_type_write_back_supported";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pde_2mb_support
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "pde_2mb_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace pdpte_1gb_support
        {
            constexpr const auto mask = 0x0000000000020000ULL;
            constexpr const auto from = 17;
            constexpr const auto name = "pdpte_1gb_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invept_support
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "invept_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace accessed_dirty_support
        {
            constexpr const auto mask = 0x0000000000200000ULL;
            constexpr const auto from = 21;
            constexpr const auto name = "accessed_dirty_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invept_single_context_support
        {
            constexpr const auto mask = 0x0000000002000000ULL;
            constexpr const auto from = 25;
            constexpr const auto name = "invept_single_context_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invept_all_context_support
        {
            constexpr const auto mask = 0x0000000004000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "invept_all_context_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invvpid_support
        {
            constexpr const auto mask = 0x0000000100000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "invvpid_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invvpid_individual_address_support
        {
            constexpr const auto mask = 0x0000010000000000ULL;
            constexpr const auto from = 40;
            constexpr const auto name = "invvpid_individual_address_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invvpid_single_context_support
        {
            constexpr const auto mask = 0x0000020000000000ULL;
            constexpr const auto from = 41;
            constexpr const auto name = "invvpid_single_context_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invvpid_all_context_support
        {
            constexpr const auto mask = 0x0000040000000000ULL;
            constexpr const auto from = 42;
            constexpr const auto name = "invvpid_all_context_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace invvpid_single_context_retaining_globals_support
        {
            constexpr const auto mask = 0x0000080000000000ULL;
            constexpr const auto from = 43;
            constexpr const auto name = "invvpid_single_context_retaining_globals_support";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_ept_vpid_cap enabled flags:" << bfendl;

            if (execute_only_translation::get()) {
                bfdebug << "    - " << execute_only_translation::name << bfendl;
            }
            if (page_walk_length_of_4::get()) {
                bfdebug << "    - " << page_walk_length_of_4::name << bfendl;
            }
            if (memory_type_uncacheable_supported::get()) {
                bfdebug << "    - " << memory_type_uncacheable_supported::name << bfendl;
            }
            if (memory_type_write_back_supported::get()) {
                bfdebug << "    - " << memory_type_write_back_supported::name << bfendl;
            }
            if (pde_2mb_support::get()) {
                bfdebug << "    - " << pde_2mb_support::name << bfendl;
            }
            if (pdpte_1gb_support::get()) {
                bfdebug << "    - " << pdpte_1gb_support::name << bfendl;
            }
            if (invept_support::get()) {
                bfdebug << "    - " << invept_support::name << bfendl;
            }
            if (accessed_dirty_support::get()) {
                bfdebug << "    - " << accessed_dirty_support::name << bfendl;
            }
            if (invept_single_context_support::get()) {
                bfdebug << "    - " << invept_single_context_support::name << bfendl;
            }
            if (invept_all_context_support::get()) {
                bfdebug << "    - " << invept_all_context_support::name << bfendl;
            }
            if (invvpid_support::get()) {
                bfdebug << "    - " << invvpid_support::name << bfendl;
            }
            if (invvpid_individual_address_support::get()) {
                bfdebug << "    - " << invvpid_individual_address_support::name << bfendl;
            }
            if (invvpid_single_context_support::get()) {
                bfdebug << "    - " << invvpid_single_context_support::name << bfendl;
            }
            if (invvpid_all_context_support::get()) {
                bfdebug << "    - " << invvpid_all_context_support::name << bfendl;
            }
            if (invvpid_single_context_retaining_globals_support::get()) {
                bfdebug << "    - " << invvpid_single_context_retaining_globals_support::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_true_pinbased_ctls
    {
        constexpr const auto addr = 0x0000048DUL;
        constexpr const auto name = "ia32_vmx_true_pinbased_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline auto allowed0()
        { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

        inline auto allowed1()
        { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

        namespace external_interrupt_exiting
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "external_interrupt_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace nmi_exiting
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "nmi_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace virtual_nmis
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "virtual_nmis";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace activate_vmx_preemption_timer
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "activate_vmx_preemption_timer";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace process_posted_interrupts
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "process_posted_interrupts";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls enabled flags:" << bfendl;

            if (external_interrupt_exiting::get()) {
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            }
            if (nmi_exiting::get()) {
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            }
            if (virtual_nmis::get()) {
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            }
            if (activate_vmx_preemption_timer::get()) {
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            }
            if (process_posted_interrupts::get()) {
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed0 fields:" << bfendl;

            if (external_interrupt_exiting::is_allowed0()) {
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            }
            if (nmi_exiting::is_allowed0()) {
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            }
            if (virtual_nmis::is_allowed0()) {
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            }
            if (activate_vmx_preemption_timer::is_allowed0()) {
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            }
            if (process_posted_interrupts::is_allowed0()) {
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed1 fields:" << bfendl;

            if (external_interrupt_exiting::is_allowed1()) {
                bfdebug << "    - " << external_interrupt_exiting::name << bfendl;
            }
            if (nmi_exiting::is_allowed1()) {
                bfdebug << "    - " << nmi_exiting::name << bfendl;
            }
            if (virtual_nmis::is_allowed1()) {
                bfdebug << "    - " << virtual_nmis::name << bfendl;
            }
            if (activate_vmx_preemption_timer::is_allowed1()) {
                bfdebug << "    - " << activate_vmx_preemption_timer::name << bfendl;
            }
            if (process_posted_interrupts::is_allowed1()) {
                bfdebug << "    - " << process_posted_interrupts::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_true_procbased_ctls
    {
        constexpr const auto addr = 0x0000048EUL;
        constexpr const auto name = "ia32_vmx_true_procbased_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline auto allowed0()
        { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

        inline auto allowed1()
        { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

        namespace interrupt_window_exiting
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "interrupt_window_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_tsc_offsetting
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "use_tsc_offsetting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace hlt_exiting
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "hlt_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace invlpg_exiting
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "invlpg_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace mwait_exiting
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "mwait_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdpmc_exiting
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "rdpmc_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace rdtsc_exiting
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "rdtsc_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr3_load_exiting
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "cr3_load_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr3_store_exiting
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "cr3_store_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr8_load_exiting
        {
            constexpr const auto mask = 0x0000000000080000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "cr8_load_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace cr8_store_exiting
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "cr8_store_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_tpr_shadow
        {
            constexpr const auto mask = 0x0000000000200000ULL;
            constexpr const auto from = 21;
            constexpr const auto name = "use_tpr_shadow";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace nmi_window_exiting
        {
            constexpr const auto mask = 0x0000000000400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "nmi_window_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace mov_dr_exiting
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "mov_dr_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace unconditional_io_exiting
        {
            constexpr const auto mask = 0x0000000001000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "unconditional_io_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_io_bitmaps
        {
            constexpr const auto mask = 0x0000000002000000ULL;
            constexpr const auto from = 25;
            constexpr const auto name = "use_io_bitmaps";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace monitor_trap_flag
        {
            constexpr const auto mask = 0x0000000008000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "monitor_trap_flag";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace use_msr_bitmap
        {
            constexpr const auto mask = 0x0000000010000000ULL;
            constexpr const auto from = 28;
            constexpr const auto name = "use_msr_bitmap";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace monitor_exiting
        {
            constexpr const auto mask = 0x0000000020000000ULL;
            constexpr const auto from = 29;
            constexpr const auto name = "monitor_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace pause_exiting
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "pause_exiting";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace activate_secondary_controls
        {
            constexpr const auto mask = 0x0000000080000000ULL;
            constexpr const auto from = 31;
            constexpr const auto name = "activate_secondary_controls";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_procbased_ctls enabled flags:" << bfendl;

            if (interrupt_window_exiting::get()) {
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            }
            if (use_tsc_offsetting::get()) {
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            }
            if (hlt_exiting::get()) {
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            }
            if (invlpg_exiting::get()) {
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            }
            if (mwait_exiting::get()) {
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            }
            if (rdpmc_exiting::get()) {
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            }
            if (rdtsc_exiting::get()) {
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            }
            if (cr3_load_exiting::get()) {
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            }
            if (cr3_store_exiting::get()) {
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            }
            if (cr8_load_exiting::get()) {
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            }
            if (cr8_store_exiting::get()) {
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            }
            if (use_tpr_shadow::get()) {
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            }
            if (nmi_window_exiting::get()) {
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            }
            if (mov_dr_exiting::get()) {
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            }
            if (unconditional_io_exiting::get()) {
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            }
            if (use_io_bitmaps::get()) {
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            }
            if (monitor_trap_flag::get()) {
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            }
            if (use_msr_bitmap::get()) {
                bfdebug << "    - " << use_msr_bitmap::name << bfendl;
            }
            if (monitor_exiting::get()) {
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            }
            if (pause_exiting::get()) {
                bfdebug << "    - " << pause_exiting::name << bfendl;
            }
            if (activate_secondary_controls::get()) {
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed0 fields:" << bfendl;

            if (interrupt_window_exiting::is_allowed0()) {
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            }
            if (use_tsc_offsetting::is_allowed0()) {
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            }
            if (hlt_exiting::is_allowed0()) {
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            }
            if (invlpg_exiting::is_allowed0()) {
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            }
            if (mwait_exiting::is_allowed0()) {
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            }
            if (rdpmc_exiting::is_allowed0()) {
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            }
            if (rdtsc_exiting::is_allowed0()) {
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            }
            if (cr3_load_exiting::is_allowed0()) {
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            }
            if (cr3_store_exiting::is_allowed0()) {
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            }
            if (cr8_load_exiting::is_allowed0()) {
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            }
            if (cr8_store_exiting::is_allowed0()) {
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            }
            if (use_tpr_shadow::is_allowed0()) {
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            }
            if (nmi_window_exiting::is_allowed0()) {
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            }
            if (mov_dr_exiting::is_allowed0()) {
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            }
            if (unconditional_io_exiting::is_allowed0()) {
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            }
            if (use_io_bitmaps::is_allowed0()) {
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            }
            if (monitor_trap_flag::is_allowed0()) {
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            }
            if (use_msr_bitmap::is_allowed0()) {
                bfdebug << "    - " << use_msr_bitmap::name << bfendl;
            }
            if (monitor_exiting::is_allowed0()) {
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            }
            if (pause_exiting::is_allowed0()) {
                bfdebug << "    - " << pause_exiting::name << bfendl;
            }
            if (activate_secondary_controls::is_allowed0()) {
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_pinbased_ctls allowed1 fields:" << bfendl;

            if (interrupt_window_exiting::is_allowed1()) {
                bfdebug << "    - " << interrupt_window_exiting::name << bfendl;
            }
            if (use_tsc_offsetting::is_allowed1()) {
                bfdebug << "    - " << use_tsc_offsetting::name << bfendl;
            }
            if (hlt_exiting::is_allowed1()) {
                bfdebug << "    - " << hlt_exiting::name << bfendl;
            }
            if (invlpg_exiting::is_allowed1()) {
                bfdebug << "    - " << invlpg_exiting::name << bfendl;
            }
            if (mwait_exiting::is_allowed1()) {
                bfdebug << "    - " << mwait_exiting::name << bfendl;
            }
            if (rdpmc_exiting::is_allowed1()) {
                bfdebug << "    - " << rdpmc_exiting::name << bfendl;
            }
            if (rdtsc_exiting::is_allowed1()) {
                bfdebug << "    - " << rdtsc_exiting::name << bfendl;
            }
            if (cr3_load_exiting::is_allowed1()) {
                bfdebug << "    - " << cr3_load_exiting::name << bfendl;
            }
            if (cr3_store_exiting::is_allowed1()) {
                bfdebug << "    - " << cr3_store_exiting::name << bfendl;
            }
            if (cr8_load_exiting::is_allowed1()) {
                bfdebug << "    - " << cr8_load_exiting::name << bfendl;
            }
            if (cr8_store_exiting::is_allowed1()) {
                bfdebug << "    - " << cr8_store_exiting::name << bfendl;
            }
            if (use_tpr_shadow::is_allowed1()) {
                bfdebug << "    - " << use_tpr_shadow::name << bfendl;
            }
            if (nmi_window_exiting::is_allowed1()) {
                bfdebug << "    - " << nmi_window_exiting::name << bfendl;
            }
            if (mov_dr_exiting::is_allowed1()) {
                bfdebug << "    - " << mov_dr_exiting::name << bfendl;
            }
            if (unconditional_io_exiting::is_allowed1()) {
                bfdebug << "    - " << unconditional_io_exiting::name << bfendl;
            }
            if (use_io_bitmaps::is_allowed1()) {
                bfdebug << "    - " << use_io_bitmaps::name << bfendl;
            }
            if (monitor_trap_flag::is_allowed1()) {
                bfdebug << "    - " << monitor_trap_flag::name << bfendl;
            }
            if (use_msr_bitmap::is_allowed1()) {
                bfdebug << "    - " << use_msr_bitmap::name << bfendl;
            }
            if (monitor_exiting::is_allowed1()) {
                bfdebug << "    - " << monitor_exiting::name << bfendl;
            }
            if (pause_exiting::is_allowed1()) {
                bfdebug << "    - " << pause_exiting::name << bfendl;
            }
            if (activate_secondary_controls::is_allowed1()) {
                bfdebug << "    - " << activate_secondary_controls::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_true_exit_ctls
    {
        constexpr const auto addr = 0x0000048FUL;
        constexpr const auto name = "ia32_vmx_true_exit_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline auto allowed0()
        { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

        inline auto allowed1()
        { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

        namespace save_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "save_debug_controls";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace host_address_space_size
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "host_address_space_size";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace acknowledge_interrupt_on_exit
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "acknowledge_interrupt_on_exit";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_ia32_pat
        {
            constexpr const auto mask = 0x0000000000040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "save_ia32_pat";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000080000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_ia32_efer
        {
            constexpr const auto mask = 0x0000000000100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "save_ia32_efer";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000200000ULL;
            constexpr const auto from = 21;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace save_vmx_preemption_timer_value
        {
            constexpr const auto mask = 0x0000000000400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "save_vmx_preemption_timer_value";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace clear_ia32_bndcfgs
        {
            constexpr const auto mask = 0x0000000000800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "clear_ia32_bndcfgs";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_exit_ctls enabled flags:" << bfendl;

            if (save_debug_controls::get()) {
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            }
            if (host_address_space_size::get()) {
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::get()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (acknowledge_interrupt_on_exit::get()) {
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            }
            if (save_ia32_pat::get()) {
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            }
            if (load_ia32_pat::get()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (save_ia32_efer::get()) {
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            }
            if (load_ia32_efer::get()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (save_vmx_preemption_timer_value::get()) {
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;
            }
            if (clear_ia32_bndcfgs::get()) {
                bfdebug << "    - " << clear_ia32_bndcfgs::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_exit_ctls allowed0 fields:" << bfendl;

            if (save_debug_controls::is_allowed0()) {
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            }
            if (host_address_space_size::is_allowed0()) {
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::is_allowed0()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (acknowledge_interrupt_on_exit::is_allowed0()) {
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            }
            if (save_ia32_pat::is_allowed0()) {
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            }
            if (load_ia32_pat::is_allowed0()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (save_ia32_efer::is_allowed0()) {
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            }
            if (load_ia32_efer::is_allowed0()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (save_vmx_preemption_timer_value::is_allowed0()) {
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;
            }
            if (clear_ia32_bndcfgs::is_allowed0()) {
                bfdebug << "    - " << clear_ia32_bndcfgs::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_exit_ctls allowed1 fields:" << bfendl;

            if (save_debug_controls::is_allowed1()) {
                bfdebug << "    - " << save_debug_controls::name << bfendl;
            }
            if (host_address_space_size::is_allowed1()) {
                bfdebug << "    - " << host_address_space_size::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::is_allowed1()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (acknowledge_interrupt_on_exit::is_allowed1()) {
                bfdebug << "    - " << acknowledge_interrupt_on_exit::name << bfendl;
            }
            if (save_ia32_pat::is_allowed1()) {
                bfdebug << "    - " << save_ia32_pat::name << bfendl;
            }
            if (load_ia32_pat::is_allowed1()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (save_ia32_efer::is_allowed1()) {
                bfdebug << "    - " << save_ia32_efer::name << bfendl;
            }
            if (load_ia32_efer::is_allowed1()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (save_vmx_preemption_timer_value::is_allowed1()) {
                bfdebug << "    - " << save_vmx_preemption_timer_value::name << bfendl;
            }
            if (clear_ia32_bndcfgs::is_allowed1()) {
                bfdebug << "    - " << clear_ia32_bndcfgs::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_true_entry_ctls
    {
        constexpr const auto addr = 0x00000490UL;
        constexpr const auto name = "ia32_vmx_true_entry_ctls";

        inline auto get() noexcept
        { return _read_msr(addr); }

        inline auto allowed0()
        { return (_read_msr(addr) & 0x00000000FFFFFFFFULL); }

        inline auto allowed1()
        { return ((_read_msr(addr) & 0xFFFFFFFF00000000ULL) >> 32); }

        namespace load_debug_controls
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "load_debug_controls";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace ia_32e_mode_guest
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "ia_32e_mode_guest";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace entry_to_smm
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "entry_to_smm";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace deactivate_dual_monitor_treatment
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "deactivate_dual_monitor_treatment";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_perf_global_ctrl
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "load_ia32_perf_global_ctrl";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_pat
        {
            constexpr const auto mask = 0x0000000000004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "load_ia32_pat";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_efer
        {
            constexpr const auto mask = 0x0000000000008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "load_ia32_efer";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        namespace load_ia32_bndcfgs
        {
            constexpr const auto mask = 0x0000000000010000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "load_ia32_bndcfgs";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline auto is_allowed0() noexcept
            { return (_read_msr(addr) & mask) == 0; }

            inline auto is_allowed1() noexcept
            { return (_read_msr(addr) & (mask << 32)) != 0; }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_vmx_true_entry_ctls enabled flags:" << bfendl;

            if (load_debug_controls::get()) {
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            }
            if (ia_32e_mode_guest::get()) {
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            }
            if (entry_to_smm::get()) {
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            }
            if (deactivate_dual_monitor_treatment::get()) {
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::get()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (load_ia32_pat::get()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (load_ia32_efer::get()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (load_ia32_bndcfgs::get()) {
                bfdebug << "    - " << load_ia32_bndcfgs::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_entry_ctls allowed0 fields:" << bfendl;

            if (load_debug_controls::is_allowed0()) {
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            }
            if (ia_32e_mode_guest::is_allowed0()) {
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            }
            if (entry_to_smm::is_allowed0()) {
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            }
            if (deactivate_dual_monitor_treatment::is_allowed0()) {
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::is_allowed0()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (load_ia32_pat::is_allowed0()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (load_ia32_efer::is_allowed0()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (load_ia32_bndcfgs::is_allowed0()) {
                bfdebug << "    - " << load_ia32_bndcfgs::name << bfendl;
            }

            bfdebug << bfendl;
            bfdebug << "msrs::ia32_vmx_true_entry_ctls allowed1 fields:" << bfendl;

            if (load_debug_controls::is_allowed1()) {
                bfdebug << "    - " << load_debug_controls::name << bfendl;
            }
            if (ia_32e_mode_guest::is_allowed1()) {
                bfdebug << "    - " << ia_32e_mode_guest::name << bfendl;
            }
            if (entry_to_smm::is_allowed1()) {
                bfdebug << "    - " << entry_to_smm::name << bfendl;
            }
            if (deactivate_dual_monitor_treatment::is_allowed1()) {
                bfdebug << "    - " << deactivate_dual_monitor_treatment::name << bfendl;
            }
            if (load_ia32_perf_global_ctrl::is_allowed1()) {
                bfdebug << "    - " << load_ia32_perf_global_ctrl::name << bfendl;
            }
            if (load_ia32_pat::is_allowed1()) {
                bfdebug << "    - " << load_ia32_pat::name << bfendl;
            }
            if (load_ia32_efer::is_allowed1()) {
                bfdebug << "    - " << load_ia32_efer::name << bfendl;
            }
            if (load_ia32_bndcfgs::is_allowed1()) {
                bfdebug << "    - " << load_ia32_bndcfgs::name << bfendl;
            }
        }
    }

    namespace ia32_vmx_vmfunc
    {
        constexpr const auto addr = 0x00000491UL;
        constexpr const auto name = "ia32_vmx_vmfunc";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace eptp_switching
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "eptp_switching";

            inline auto is_allowed1()
            { return is_bit_set(_read_msr(addr), from); }
        }
    }

    namespace ia32_a_pmc0
    {
        constexpr const auto addr = 0x000004C1UL;
        constexpr const auto name = "ia32_a_pmc0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc1
    {
        constexpr const auto addr = 0x000004C2UL;
        constexpr const auto name = "ia32_a_pmc1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc2
    {
        constexpr const auto addr = 0x000004C3UL;
        constexpr const auto name = "ia32_a_pmc2";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc3
    {
        constexpr const auto addr = 0x000004C4UL;
        constexpr const auto name = "ia32_a_pmc3";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc4
    {
        constexpr const auto addr = 0x000004C5UL;
        constexpr const auto name = "ia32_a_pmc4";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc5
    {
        constexpr const auto addr = 0x000004C6UL;
        constexpr const auto name = "ia32_a_pmc5";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc6
    {
        constexpr const auto addr = 0x000004C7UL;
        constexpr const auto name = "ia32_a_pmc6";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_a_pmc7
    {
        constexpr const auto addr = 0x000004C8UL;
        constexpr const auto name = "ia32_a_pmc7";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_mcg_ext_ctl
    {
        constexpr const auto addr = 0x000004D0UL;
        constexpr const auto name = "ia32_mcg_ext_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace lmce_en
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lmce_en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_sgx_svn_sinit
    {
        constexpr const auto addr = 0x00000500UL;
        constexpr const auto name = "ia32_sgx_svn_sinit";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace lock
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lock";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace sgx_svn_sinit
        {
            constexpr const auto mask = 0x0000000000FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "sgx_svn_sinit";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_rtit_output_base
    {
        constexpr const auto addr = 0x00000560UL;
        constexpr const auto name = "ia32_rtit_output_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace base_phys_address
        {
            constexpr const auto mask = 0x7FFFFFFFFFFFFF80ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "base_phys_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_output_mask_ptrs
    {
        constexpr const auto addr = 0x00000561UL;
        constexpr const auto name = "ia32_rtit_output_mask_ptrs";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace mask_table_offset
        {
            constexpr const auto mask = 0x00000000FFFFFF80ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "mask_table_offset";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace output_offset
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "output_offset";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_ctl
    {
        constexpr const auto addr = 0x00000570UL;
        constexpr const auto name = "ia32_rtit_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace traceen
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "traceen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace cycen
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "cycen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace os
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "os";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace user
        {
            constexpr const auto mask = 0x0000000000000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "user";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace fabricen
        {
            constexpr const auto mask = 0x0000000000000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "fabricen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace cr3_filter
        {
            constexpr const auto mask = 0x0000000000000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "cr3_filter";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace topa
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "topa";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace mtcen
        {
            constexpr const auto mask = 0x0000000000000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "mtcen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace tscen
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "tscen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace disretc
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "disretc";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace branchen
        {
            constexpr const auto mask = 0x0000000000002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "branchen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace mtcfreq
        {
            constexpr const auto mask = 0x000000000003C000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "mtcfreq";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cycthresh
        {
            constexpr const auto mask = 0x0000000000780000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "cycthresh";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace psbfreq
        {
            constexpr const auto mask = 0x000000000F000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "psbfreq";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace addr0_cfg
        {
            constexpr const auto mask = 0x0000000F00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "addr0_cfg";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace addr1_cfg
        {
            constexpr const auto mask = 0x000000F000000000ULL;
            constexpr const auto from = 36;
            constexpr const auto name = "addr1_cfg";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace addr2_cfg
        {
            constexpr const auto mask = 0x00000F0000000000ULL;
            constexpr const auto from = 40;
            constexpr const auto name = "addr2_cfg";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace addr3_cfg
        {
            constexpr const auto mask = 0x0000F00000000000ULL;
            constexpr const auto from = 44;
            constexpr const auto name = "addr3_cfg";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_status
    {
        constexpr const auto addr = 0x00000571UL;
        constexpr const auto name = "ia32_rtit_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace filteren
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "filteren";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace contexen
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "contexen";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace triggeren
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "triggeren";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace error
        {
            constexpr const auto mask = 0x0000000000000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "error";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace stopped
        {
            constexpr const auto mask = 0x0000000000000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "stopped";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace packetbytecnt
        {
            constexpr const auto mask = 0x0001FFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "packetbytecnt";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_cr3_match
    {
        constexpr const auto addr = 0x00000572UL;
        constexpr const auto name = "ia32_rtit_cr3_match";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace cr3
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFFFE0ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "cr3";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr0_a
    {
        constexpr const auto addr = 0x00000580UL;
        constexpr const auto name = "ia32_rtit_addr0_a";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr0_b
    {
        constexpr const auto addr = 0x00000581UL;
        constexpr const auto name = "ia32_rtit_addr0_b";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr1_a
    {
        constexpr const auto addr = 0x00000582UL;
        constexpr const auto name = "ia32_rtit_addr1_a";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr1_b
    {
        constexpr const auto addr = 0x00000583UL;
        constexpr const auto name = "ia32_rtit_addr1_b";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr2_a
    {
        constexpr const auto addr = 0x00000584UL;
        constexpr const auto name = "ia32_rtit_addr2_a";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr2_b
    {
        constexpr const auto addr = 0x00000585UL;
        constexpr const auto name = "ia32_rtit_addr2_b";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr3_a
    {
        constexpr const auto addr = 0x00000586UL;
        constexpr const auto name = "ia32_rtit_addr3_a";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_rtit_addr3_b
    {
        constexpr const auto addr = 0x00000587UL;
        constexpr const auto name = "ia32_rtit_addr3_b";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace virtual_address
        {
            constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "virtual_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace signext_va
        {
            constexpr const auto mask = 0xFFFF000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "signext_va";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_ds_area
    {
        constexpr const auto addr = 0x00000600UL;
        constexpr const auto name = "ia32_ds_area";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_tsc_deadline
    {
        constexpr const auto addr = 0x000006E0UL;
        constexpr const auto name = "ia32_tsc_deadline";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_pm_enable
    {
        constexpr const auto addr = 0x00000770UL;
        constexpr const auto name = "ia32_pm_enable";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace hwp
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "sce";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_hwp_capabilities
    {
        constexpr const auto addr = 0x00000771UL;
        constexpr const auto name = "ia32_hwp_capabilities";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace highest_perf
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "highest_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace guaranteed_perf
        {
            constexpr const auto mask = 0x000000000000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "guaranteed_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace most_efficient_perf
        {
            constexpr const auto mask = 0x0000000000FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "most_efficient_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace lowest_perf
        {
            constexpr const auto mask = 0x00000000FF000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "lowest_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }
    }

    namespace ia32_hwp_request_pkg
    {
        constexpr const auto addr = 0x00000772UL;
        constexpr const auto name = "ia32_hwp_request_pkg";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace min_perf
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "min_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace max_perf
        {
            constexpr const auto mask = 0x000000000000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "max_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace desired_perf
        {
            constexpr const auto mask = 0x0000000000FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "desired_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace energy_perf_pref
        {
            constexpr const auto mask = 0x00000000FF000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "energy_perf_pref";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace activity_window
        {
            constexpr const auto mask = 0x000003FF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "activity_window";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_hwp_interrupt
    {
        constexpr const auto addr = 0x00000773UL;
        constexpr const auto name = "ia32_hwp_interrupt";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace perf_change
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "perf_change";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace excursion_min
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "excursion_min";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_hwp_request
    {
        constexpr const auto addr = 0x00000774UL;
        constexpr const auto name = "ia32_hwp_request";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace min_perf
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "min_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace max_perf
        {
            constexpr const auto mask = 0x000000000000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "max_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace desired_perf
        {
            constexpr const auto mask = 0x0000000000FF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "desired_perf";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace energy_perf_pref
        {
            constexpr const auto mask = 0x00000000FF000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "energy_perf_pref";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace activity_window
        {
            constexpr const auto mask = 0x000003FF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "energy_perf_pref";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace package_control
        {
            constexpr const auto mask = 0x0000040000000000ULL;
            constexpr const auto from = 42;
            constexpr const auto name = "package_control";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_hwp_status
    {
        constexpr const auto addr = 0x00000777UL;
        constexpr const auto name = "ia32_hwp_status";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace perf_change
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "perf_change";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace excursion_to_min
        {
            constexpr const auto mask = 0x0000000000000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "excursion_to_min";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_x2apic_apicid
    {
        constexpr const auto addr = 0x00000802UL;
        constexpr const auto name = "ia32_x2apic_apicid";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_version
    {
        constexpr const auto addr = 0x00000803UL;
        constexpr const auto name = "ia32_x2apic_version";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tpr
    {
        constexpr const auto addr = 0x00000808UL;
        constexpr const auto name = "ia32_x2apic_tpr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_ppr
    {
        constexpr const auto addr = 0x0000080AUL;
        constexpr const auto name = "ia32_x2apic_ppr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_eoi
    {
        constexpr const auto addr = 0x0000080BUL;
        constexpr const auto name = "ia32_x2apic_eoi";

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_ldr
    {
        constexpr const auto addr = 0x0000080DUL;
        constexpr const auto name = "ia32_x2apic_ldr";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_sivr
    {
        constexpr const auto addr = 0x0000080FUL;
        constexpr const auto name = "ia32_x2apic_sivr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_isr0
    {
        constexpr const auto addr = 0x00000810UL;
        constexpr const auto name = "ia32_x2apic_isr0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr1
    {
        constexpr const auto addr = 0x00000811UL;
        constexpr const auto name = "ia32_x2apic_isr1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr2
    {
        constexpr const auto addr = 0x00000812UL;
        constexpr const auto name = "ia32_x2apic_isr2";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr3
    {
        constexpr const auto addr = 0x00000813UL;
        constexpr const auto name = "ia32_x2apic_isr3";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr4
    {
        constexpr const auto addr = 0x00000814UL;
        constexpr const auto name = "ia32_x2apic_isr4";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr5
    {
        constexpr const auto addr = 0x00000815UL;
        constexpr const auto name = "ia32_x2apic_isr5";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr6
    {
        constexpr const auto addr = 0x00000816UL;
        constexpr const auto name = "ia32_x2apic_isr6";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_isr7
    {
        constexpr const auto addr = 0x00000817UL;
        constexpr const auto name = "ia32_x2apic_isr7";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr0
    {
        constexpr const auto addr = 0x00000818UL;
        constexpr const auto name = "ia32_x2apic_tmr0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr1
    {
        constexpr const auto addr = 0x00000819UL;
        constexpr const auto name = "ia32_x2apic_tmr1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr2
    {
        constexpr const auto addr = 0x0000081AUL;
        constexpr const auto name = "ia32_x2apic_tmr2";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr3
    {
        constexpr const auto addr = 0x0000081BUL;
        constexpr const auto name = "ia32_x2apic_tmr3";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr4
    {
        constexpr const auto addr = 0x0000081CUL;
        constexpr const auto name = "ia32_x2apic_tmr4";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr5
    {
        constexpr const auto addr = 0x0000081DUL;
        constexpr const auto name = "ia32_x2apic_tmr5";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr6
    {
        constexpr const auto addr = 0x0000081EUL;
        constexpr const auto name = "ia32_x2apic_tmr6";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_tmr7
    {
        constexpr const auto addr = 0x0000081FUL;
        constexpr const auto name = "ia32_x2apic_tmr7";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr0
    {
        constexpr const auto addr = 0x00000820UL;
        constexpr const auto name = "ia32_x2apic_irr0";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr1
    {
        constexpr const auto addr = 0x00000821UL;
        constexpr const auto name = "ia32_x2apic_irr1";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr2
    {
        constexpr const auto addr = 0x00000822UL;
        constexpr const auto name = "ia32_x2apic_irr2";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr3
    {
        constexpr const auto addr = 0x00000823UL;
        constexpr const auto name = "ia32_x2apic_irr3";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr4
    {
        constexpr const auto addr = 0x00000824UL;
        constexpr const auto name = "ia32_x2apic_irr4";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr5
    {
        constexpr const auto addr = 0x00000825UL;
        constexpr const auto name = "ia32_x2apic_irr5";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr6
    {
        constexpr const auto addr = 0x00000826UL;
        constexpr const auto name = "ia32_x2apic_irr6";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_irr7
    {
        constexpr const auto addr = 0x00000827UL;
        constexpr const auto name = "ia32_x2apic_irr7";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_esr
    {
        constexpr const auto addr = 0x00000828UL;
        constexpr const auto name = "ia32_x2apic_esr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_cmci
    {
        constexpr const auto addr = 0x0000082FUL;
        constexpr const auto name = "ia32_x2apic_lvt_cmci";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_icr
    {
        constexpr const auto addr = 0x00000830UL;
        constexpr const auto name = "ia32_x2apic_icr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_timer
    {
        constexpr const auto addr = 0x00000832UL;
        constexpr const auto name = "ia32_x2apic_lvt_timer";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_thermal
    {
        constexpr const auto addr = 0x00000833UL;
        constexpr const auto name = "ia32_x2apic_lvt_thermal";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_pmi
    {
        constexpr const auto addr = 0x00000834UL;
        constexpr const auto name = "ia32_x2apic_lvt_pmi";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_lint0
    {
        constexpr const auto addr = 0x00000835UL;
        constexpr const auto name = "ia32_x2apic_lvt_lint0";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_lint1
    {
        constexpr const auto addr = 0x00000836UL;
        constexpr const auto name = "ia32_x2apic_lvt_lint1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_lvt_error
    {
        constexpr const auto addr = 0x00000837UL;
        constexpr const auto name = "ia32_x2apic_lvt_error";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_init_count
    {
        constexpr const auto addr = 0x00000838UL;
        constexpr const auto name = "ia32_x2apic_init_count";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_cur_count
    {
        constexpr const auto addr = 0x00000839UL;
        constexpr const auto name = "ia32_x2apic_cur_count";

        inline auto get() noexcept
        { return _read_msr(addr); }
    }

    namespace ia32_x2apic_div_conf
    {
        constexpr const auto addr = 0x0000083EUL;
        constexpr const auto name = "ia32_x2apic_div_conf";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_x2apic_self_ipi
    {
        constexpr const auto addr = 0x0000083FUL;
        constexpr const auto name = "ia32_x2apic_self_ipi";

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_debug_interface
    {
        constexpr const auto addr = 0x00000C80UL;
        constexpr const auto name = "ia32_debug_interface";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace enable
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lock
        {
            constexpr const auto mask = 0x0000000040000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "lock";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace debug_occurred
        {
            constexpr const auto mask = 0x0000000080000000ULL;
            constexpr const auto from = 31;
            constexpr const auto name = "debug_occurred";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_l3_qos_cfg
    {
        constexpr const auto addr = 0x00000C81UL;
        constexpr const auto name = "ia32_l3_qos_cfg";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace enable
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_qm_evtsel
    {
        constexpr const auto addr = 0x00000C8DUL;
        constexpr const auto name = "ia32_qm_evtsel";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace event_id
        {
            constexpr const auto mask = 0x00000000000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "event_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace resource_monitoring_id
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "resource_monitoring_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_qm_ctr
    {
        constexpr const auto addr = 0x00000C8EUL;
        constexpr const auto name = "ia32_qm_ctr";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace resource_monitored_data
        {
            constexpr const auto mask = 0x3FFFFFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "resource_monitored_data";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }
        }

        namespace unavailable
        {
            constexpr const auto mask = 0x4000000000000000ULL;
            constexpr const auto from = 62;
            constexpr const auto name = "unavailable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }

        namespace error
        {
            constexpr const auto mask = 0x8000000000000000ULL;
            constexpr const auto from = 63;
            constexpr const auto name = "error";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }
        }
    }

    namespace ia32_pqr_assoc
    {
        constexpr const auto addr = 0x00000C8FUL;
        constexpr const auto name = "ia32_pqr_assoc";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace resource_monitoring_id
        {
            constexpr const auto mask = 0x00000000FFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "resource_monitoring_id";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        namespace cos
        {
            constexpr const auto mask = 0xFFFFFFFF00000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "cos";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_bndcfgs
    {
        constexpr const auto addr = 0x00000D90UL;
        constexpr const auto name = "ia32_bndcfgs";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace en
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "en";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace bndpreserve
        {
            constexpr const auto mask = 0x0000000000000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "bndpreserve";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace base_address
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "base_address";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_xss
    {
        constexpr const auto addr = 0x00000DA0UL;
        constexpr const auto name = "ia32_xss";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace trace_packet
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "trace_packet";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_pkg_hdc_ctl
    {
        constexpr const auto addr = 0x00000DB0UL;
        constexpr const auto name = "ia32_pkg_hdc_ctl";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace hdc_pkg_enable
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "hdc_pkg_enable";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_pm_ctl1
    {
        constexpr const auto addr = 0x00000DB1UL;
        constexpr const auto name = "ia32_pm_ctl1";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace hdc_allow_block
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "hdc_allow_block";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }
    }

    namespace ia32_thread_stall
    {
        constexpr const auto addr = 0x00000DB2UL;
        constexpr const auto name = "ia32_thread_stall";

        inline auto get() noexcept
        { return _read_msr(addr); }

        namespace stall_cycle_cnt
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "stall_cycle_cnt";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }
    }

    namespace ia32_efer
    {
        constexpr const auto addr = 0xC0000080UL;
        constexpr const auto name = "ia32_efer";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }

        namespace sce
        {
            constexpr const auto mask = 0x0000000000000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "sce";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lme
        {
            constexpr const auto mask = 0x0000000000000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "lme";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace lma
        {
            constexpr const auto mask = 0x0000000000000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace nxe
        {
            constexpr const auto mask = 0x0000000000000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "lma";

            inline auto get() noexcept
            { return get_bit(_read_msr(addr), from) != 0; }

            inline void set(bool val) noexcept
            { _write_msr(addr, val ? set_bit(_read_msr(addr), from) : clear_bit(_read_msr(addr), from)); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xFFFFFFFFFFFFF2FEULL;
            constexpr const auto from = 0;
            constexpr const auto name = "reserved";

            inline auto get() noexcept
            { return get_bits(_read_msr(addr), mask) >> from; }

            template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
            void set(T val) noexcept { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }
        }

        inline void dump() noexcept
        {
            bfdebug << "msrs::ia32_efer enabled flags:" << bfendl;

            if (sce::get()) {
                bfdebug << "    - " << sce::name << bfendl;
            }
            if (lme::get()) {
                bfdebug << "    - " << lme::name << bfendl;
            }
            if (lma::get()) {
                bfdebug << "    - " << lma::name << bfendl;
            }
            if (nxe::get()) {
                bfdebug << "    - " << nxe::name << bfendl;
            }
        }
    }

    namespace ia32_fs_base
    {
        constexpr const auto addr = 0xC0000100UL;
        constexpr const auto name = "ia32_fs_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }

    namespace ia32_gs_base
    {
        constexpr const auto addr = 0xC0000101UL;
        constexpr const auto name = "ia32_gs_base";

        inline auto get() noexcept
        { return _read_msr(addr); }

        template<typename T, typename =  std::enable_if<std::is_integral<T>::value>>
        void set(T val) noexcept { _write_msr(addr, val); }
    }
}
}

// *INDENT-ON*

#endif

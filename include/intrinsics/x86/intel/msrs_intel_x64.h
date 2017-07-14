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

#include <intrinsics/x86/common/msrs_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace msrs
{

using field_type = x64::msrs::field_type;
using value_type = x64::msrs::value_type;

inline auto get(field_type addr) noexcept
{ return _read_msr(addr); }

inline void set(field_type addr, value_type val) noexcept
{ _write_msr(addr, val); }

constexpr const field_type ia32_x2apic_beg = 0x00000800U;
constexpr const field_type ia32_x2apic_end = 0x00000BFFU;

namespace ia32_monitor_filter_size
{
    constexpr const auto addr = 0x00000006U;
    constexpr const auto name = "ia32_monitor_filter_size";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_platform_id
{
    constexpr const auto addr = 0x00000017U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        platform_id::dump(level);
    }
}

namespace ia32_feature_control
{
    constexpr const auto addr = 0x0000003AU;
    constexpr const auto name = "ia32_feature_control";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lock_bit
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "lock_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_vmx_inside_smx
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "enable_vmx_inside_smx";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_vmx_outside_smx
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "enable_vmx_outside_smx";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace senter_local_function_enable
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "senter_local_function_enable";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace senter_global_function_enables
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "senter_global_function_enables";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace sgx_launch_control_enable
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "sgx_launch_control_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace sgx_global_enable
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "sgx_global_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lmce
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "lmce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        lock_bit::dump(level);
        enable_vmx_inside_smx::dump(level);
        enable_vmx_outside_smx::dump(level);
        senter_local_function_enable::dump(level);
        senter_global_function_enables::dump(level);
        sgx_launch_control_enable::dump(level);
        sgx_global_enable::dump(level);
        lmce::dump(level);
    }
}

namespace ia32_tsc_adjust
{
    constexpr const auto addr = 0x0000003BU;
    constexpr const auto name = "ia32_tsc_adjust";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace thread_adjust
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "thread_adjust";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        thread_adjust::dump(level);
    }
}

namespace ia32_bios_updt_trig
{
    constexpr const auto addr = 0x00000079U;
    constexpr const auto name = "ia32_bios_updt_trig";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ia32_bios_sign_id
{
    constexpr const auto addr = 0x0000008BU;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        bios_sign_id::dump(level);
    }
}

namespace ia32_sgxlepubkeyhash0
{
    constexpr const auto addr = 0x0000008CU;
    constexpr const auto name = "ia32_sgxlepubkeyhash0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sgxlepubkeyhash1
{
    constexpr const auto addr = 0x0000008DU;
    constexpr const auto name = "ia32_sgxlepubkeyhash1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sgxlepubkeyhash2
{
    constexpr const auto addr = 0x0000008EU;
    constexpr const auto name = "ia32_sgxlepubkeyhash2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sgxlepubkeyhash3
{
    constexpr const auto addr = 0x0000008FU;
    constexpr const auto name = "ia32_sgxlepubkeyhash3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_smm_monitor_ctl
{
    constexpr const auto addr = 0x0000009BU;
    constexpr const auto name = "ia32_smm_monitor_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace vmxoff
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "vmxoff";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mseg_base
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "mseg_base";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        valid::dump(level);
        vmxoff::dump(level);
        mseg_base::dump(level);
    }
}

namespace ia32_smbase
{
    constexpr const auto addr = 0x0000009EU;
    constexpr const auto name = "ia32_smbase";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc0
{
    constexpr const auto addr = 0x000000C1U;
    constexpr const auto name = "ia32_pmc0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc1
{
    constexpr const auto addr = 0x000000C2U;
    constexpr const auto name = "ia32_pmc1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc2
{
    constexpr const auto addr = 0x000000C3U;
    constexpr const auto name = "ia32_pmc2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc3
{
    constexpr const auto addr = 0x000000C4U;
    constexpr const auto name = "ia32_pmc3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc4
{
    constexpr const auto addr = 0x000000C5U;
    constexpr const auto name = "ia32_pmc4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc5
{
    constexpr const auto addr = 0x000000C6U;
    constexpr const auto name = "ia32_pmc5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc6
{
    constexpr const auto addr = 0x000000C7U;
    constexpr const auto name = "ia32_pmc6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pmc7
{
    constexpr const auto addr = 0x000000C8U;
    constexpr const auto name = "ia32_pmc7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sysenter_cs
{
    constexpr const auto addr = 0x00000174U;
    constexpr const auto name = "ia32_sysenter_cs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sysenter_esp
{
    constexpr const auto addr = 0x00000175U;
    constexpr const auto name = "ia32_sysenter_esp";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_sysenter_eip
{
    constexpr const auto addr = 0x00000176;
    constexpr const auto name = "ia32_sysenter_eip";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_perfevtsel0
{
    constexpr const auto addr = 0x00000186;
    constexpr const auto name = "ia32_perfevtsel0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace event_select
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "event_select";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace umask
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "umask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace usr
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace os
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace edge
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "edge";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pc
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19;
        constexpr const auto name = "pc";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace interrupt
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "interrupt";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace anythread
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace inv
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "inv";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cmask
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "cmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        event_select::dump(level);
        umask::dump(level);
        usr::dump(level);
        os::dump(level);
        edge::dump(level);
        pc::dump(level);
        interrupt::dump(level);
        anythread::dump(level);
        en::dump(level);
        inv::dump(level);
        cmask::dump(level);
    }
}

namespace ia32_perfevtsel1
{
    constexpr const auto addr = 0x00000187;
    constexpr const auto name = "ia32_perfevtsel1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_perfevtsel2
{
    constexpr const auto addr = 0x00000188;
    constexpr const auto name = "ia32_perfevtsel2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_perfevtsel3
{
    constexpr const auto addr = 0x00000189;
    constexpr const auto name = "ia32_perfevtsel3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        state_value::dump(level);
    }
}

namespace ia32_perf_ctl
{
    constexpr const auto addr = 0x00000199;
    constexpr const auto name = "ia32_perf_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace state_value
    {
        constexpr const auto mask = 0x000000000000FFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "state_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace ida_engage
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "ida_engage";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        state_value::dump(level);
        ida_engage::dump(level);
    }
}

namespace ia32_clock_modulation
{
    constexpr const auto addr = 0x0000019A;
    constexpr const auto name = "ia32_clock_modulation";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace ext_duty_cycle
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "ext_duty_cycle";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace duty_cycle_values
    {
        constexpr const auto mask = 0x000000000000000EULL;
        constexpr const auto from = 1;
        constexpr const auto name = "duty_cycle_values";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace enable_modulation
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "enable_modulation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        ext_duty_cycle::dump(level);
        duty_cycle_values::dump(level);
        enable_modulation::dump(level);
    }
}

namespace ia32_therm_interrupt
{
    constexpr const auto addr = 0x0000019B;
    constexpr const auto name = "ia32_therm_interrupt";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace high_temp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "high_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace low_temp
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "low_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace prochot
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "prochot";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace forcepr
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "forcepr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace crit_temp
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "crit_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace threshold_1_value
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "threshold_1_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace threshold_1_enable
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "threshold_1_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace threshold_2_value
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "threshold_2_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace threshold_2_enable
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "threshold_2_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace power_limit
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "power_limit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        high_temp::dump(level);
        low_temp::dump(level);
        prochot::dump(level);
        forcepr::dump(level);
        crit_temp::dump(level);
        threshold_1_value::dump(level);
        threshold_1_enable::dump(level);
        threshold_2_value::dump(level);
        threshold_2_enable::dump(level);
        power_limit::dump(level);
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace thermal_status_log
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "thermal_status_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace forcepr_event
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "forcepr_event";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace forcepr_log
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "forcepr_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace crit_temp_status
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "crit_temp_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace crit_temp_log
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "crit_temp_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace therm_threshold1_status
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "therm_threshold1_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace therm_threshold1_log
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "therm_threshold1_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace therm_threshold2_status
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "therm_threshold2_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace therm_threshold2_log
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "therm_threshold2_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace power_limit_status
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "power_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace power_limit_log
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "power_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace current_limit_status
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "current_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace current_limit_log
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "current_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cross_domain_status
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "cross_domain_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cross_domain_log
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "cross_domain_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace digital_readout
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "digital_readout";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace resolution_celcius
    {
        constexpr const auto mask = 0x0000000078000000ULL;
        constexpr const auto from = 27;
        constexpr const auto name = "resolution_celcius";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace reading_valid
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31;
        constexpr const auto name = "reading_valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        therm_status::dump(level);
        thermal_status_log::dump(level);
        forcepr_event::dump(level);
        forcepr_log::dump(level);
        crit_temp_status::dump(level);
        crit_temp_log::dump(level);
        therm_threshold1_status::dump(level);
        therm_threshold1_log::dump(level);
        therm_threshold2_status::dump(level);
        therm_threshold2_log::dump(level);
        power_limit_status::dump(level);
        power_limit_log::dump(level);
        current_limit_status::dump(level);
        current_limit_log::dump(level);
        cross_domain_status::dump(level);
        cross_domain_log::dump(level);
        digital_readout::dump(level);
        resolution_celcius::dump(level);
        reading_valid::dump(level);
    }
}

namespace ia32_misc_enable
{
    constexpr const auto addr = 0x000001A0U;
    constexpr const auto name = "ia32_misc_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace fast_strings
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "fast_strings";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace auto_therm_control
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "auto_therm_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace perf_monitor
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "perf_monitor";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace branch_trace_storage
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "branch_trace_storage";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace processor_sampling
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "processor_sampling";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace intel_speedstep
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "intel_speedstep";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace monitor_fsm
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "monitor_fsm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace limit_cpuid_maxval
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "limit_cpuid_maxval";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace xtpr_message
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "xtpr_message";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace xd_bit
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "xd_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        fast_strings::dump(level);
        auto_therm_control::dump(level);
        perf_monitor::dump(level);
        branch_trace_storage::dump(level);
        processor_sampling::dump(level);
        intel_speedstep::dump(level);
        monitor_fsm::dump(level);
        limit_cpuid_maxval::dump(level);
        xtpr_message::dump(level);
        xd_bit::dump(level);
    }
}

namespace ia32_energy_perf_bias
{
    constexpr const auto addr = 0x000001B0U;
    constexpr const auto name = "ia32_energy_perf_bias";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace power_policy
    {
        constexpr const auto mask = 0x000000000000000FULL;
        constexpr const auto from = 0;
        constexpr const auto name = "power_policy";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        power_policy::dump(level);
    }
}

namespace ia32_package_therm_status
{
    constexpr const auto addr = 0x000001B1U;
    constexpr const auto name = "ia32_package_therm_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace pkg_therm_status
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "pkg_therm_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_therm_log
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "pkg_therm_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_prochot_event
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "pkg_prochot_event";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_prochot_log
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pkg_prochot_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_crit_temp_status
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pkg_crit_temp_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_crit_temp_log
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "pkg_crit_temp_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_therm_thresh1_status
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "pkg_therm_thresh1_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_therm_thresh1_log
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "pkg_therm_thresh1_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_therm_thresh2_status
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "pkg_therm_thresh2_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_therm_thresh2_log
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "pkg_therm_thresh2_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_power_limit_status
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "pkg_power_limit_status";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_power_limit_log
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "pkg_power_limit_log";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_digital_readout
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "pkg_digital_readout";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        pkg_therm_status::dump(level);
        pkg_therm_log::dump(level);
        pkg_prochot_event::dump(level);
        pkg_prochot_log::dump(level);
        pkg_crit_temp_status::dump(level);
        pkg_crit_temp_log::dump(level);
        pkg_therm_thresh1_status::dump(level);
        pkg_therm_thresh1_log::dump(level);
        pkg_therm_thresh2_status::dump(level);
        pkg_therm_thresh2_log::dump(level);
        pkg_power_limit_status::dump(level);
        pkg_power_limit_log::dump(level);
        pkg_digital_readout::dump(level);
    }
}

namespace ia32_package_therm_interrupt
{
    constexpr const auto addr = 0x000001B2U;
    constexpr const auto name = "ia32_energy_perf_bias";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pkg_high_temp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "pkg_high_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_low_temp
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "pkg_low_temp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_prochot
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "pkg_prochot";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_overheat
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pkg_overheat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_threshold_1_value
    {
        constexpr const auto mask = 0x0000000000007F00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "pkg_threshold_1_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace pkg_threshold_1_enable
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "pkg_threshold_1_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_threshold_2_value
    {
        constexpr const auto mask = 0x00000000007F0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "pkg_threshold_2_value";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace pkg_threshold_2_enable
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "pkg_threshold_2_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pkg_power_limit
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "pkg_power_limit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        pkg_high_temp::dump(level);
        pkg_low_temp::dump(level);
        pkg_prochot::dump(level);
        pkg_overheat::dump(level);
        pkg_threshold_1_value::dump(level);
        pkg_threshold_1_enable::dump(level);
        pkg_threshold_2_value::dump(level);
        pkg_threshold_2_enable::dump(level);
        pkg_power_limit::dump(level);
    }
}

namespace ia32_debugctl
{
    constexpr const auto addr = 0x000001D9U;
    constexpr const auto name = "ia32_debugctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lbr
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "lbr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace btf
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "btf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace tr
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "tr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace bts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "bts";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace btint
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "btint";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace bt_off_os
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "bt_off_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace bt_off_user
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "bt_off_user";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace freeze_lbrs_on_pmi
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "freeze_lbrs_on_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace freeze_perfmon_on_pmi
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "freeze_perfmon_on_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_uncore_pmi
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_uncore_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace freeze_while_smm
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "freeze_while_smm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rtm_debug
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "rtm_debug";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        lbr::dump(level);
        btf::dump(level);
        tr::dump(level);
        bts::dump(level);
        btint::dump(level);
        bt_off_os::dump(level);
        bt_off_user::dump(level);
        freeze_lbrs_on_pmi::dump(level);
        freeze_perfmon_on_pmi::dump(level);
        enable_uncore_pmi::dump(level);
        freeze_while_smm::dump(level);
        rtm_debug::dump(level);
    }
}

namespace ia32_smrr_physbase
{
    constexpr const auto addr = 0x000001F2U;
    constexpr const auto name = "ia32_smrr_physbase";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace type
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace physbase
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "physbase";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        type::dump(level);
        physbase::dump(level);
    }
}

namespace ia32_smrr_physmask
{
    constexpr const auto addr = 0x000001F3U;
    constexpr const auto name = "ia32_smrr_physmask";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace valid
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "valid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace physmask
    {
        constexpr const auto mask = 0x00000000FFFFF000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "physmask";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        valid::dump(level);
        physmask::dump(level);
    }
}

namespace ia32_platform_dca_cap
{
    constexpr const auto addr = 0x000001F8U;
    constexpr const auto name = "ia32_platform_dca_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_cpu_dca_cap
{
    constexpr const auto addr = 0x000001F9U;
    constexpr const auto name = "ia32_cpu_dca_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_dca_0_cap
{
    constexpr const auto addr = 0x000001FAU;
    constexpr const auto name = "ia32_dca_0_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace dca_active
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "dca_active";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace transaction
    {
        constexpr const auto mask = 0x0000000000000006ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "transaction";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace dca_type
    {
        constexpr const auto mask = 0x0000000000000078ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "dca_type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace dca_queue_size
    {
        constexpr const auto mask = 0x0000000000000780ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "dca_queue_size";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace dca_delay
    {
        constexpr const auto mask = 0x000000000001E000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "dca_delay";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace sw_block
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "sw_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace hw_block
    {
        constexpr const auto mask = 0x0000000004000000ULL;
        constexpr const auto from = 26;
        constexpr const auto name = "hw_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        dca_active::dump(level);
        transaction::dump(level);
        dca_type::dump(level);
        dca_queue_size::dump(level);
        dca_delay::dump(level);
        sw_block::dump(level);
        hw_block::dump(level);
    }
}

namespace ia32_mtrr_physbase0
{
    constexpr const auto addr = 0x00000200U;
    constexpr const auto name = "ia32_mtrr_physbase0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask0
{
    constexpr const auto addr = 0x00000201U;
    constexpr const auto name = "ia32_mtrr_physmask0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase1
{
    constexpr const auto addr = 0x00000202U;
    constexpr const auto name = "ia32_mtrr_physbase1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask1
{
    constexpr const auto addr = 0x00000203U;
    constexpr const auto name = "ia32_mtrr_physmask1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase2
{
    constexpr const auto addr = 0x00000204U;
    constexpr const auto name = "ia32_mtrr_physbase2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask2
{
    constexpr const auto addr = 0x00000205U;
    constexpr const auto name = "ia32_mtrr_physmask2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase3
{
    constexpr const auto addr = 0x00000206U;
    constexpr const auto name = "ia32_mtrr_physbase3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask3
{
    constexpr const auto addr = 0x00000207U;
    constexpr const auto name = "ia32_mtrr_physmask3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase4
{
    constexpr const auto addr = 0x00000208U;
    constexpr const auto name = "ia32_mtrr_physbase4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask4
{
    constexpr const auto addr = 0x00000209U;
    constexpr const auto name = "ia32_mtrr_physmask4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase5
{
    constexpr const auto addr = 0x0000020AU;
    constexpr const auto name = "ia32_mtrr_physbase5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask5
{
    constexpr const auto addr = 0x0000020BU;
    constexpr const auto name = "ia32_mtrr_physmask5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase6
{
    constexpr const auto addr = 0x0000020CU;
    constexpr const auto name = "ia32_mtrr_physbase6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask6
{
    constexpr const auto addr = 0x0000020DU;
    constexpr const auto name = "ia32_mtrr_physmask6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase7
{
    constexpr const auto addr = 0x0000020EU;
    constexpr const auto name = "ia32_mtrr_physbase7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask7
{
    constexpr const auto addr = 0x0000020FU;
    constexpr const auto name = "ia32_mtrr_physmask7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase8
{
    constexpr const auto addr = 0x00000210U;
    constexpr const auto name = "ia32_mtrr_physbase8";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask8
{
    constexpr const auto addr = 0x00000211U;
    constexpr const auto name = "ia32_mtrr_physmask8";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physbase9
{
    constexpr const auto addr = 0x00000212U;
    constexpr const auto name = "ia32_mtrr_physbase9";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_physmask9
{
    constexpr const auto addr = 0x00000213U;
    constexpr const auto name = "ia32_mtrr_physmask9";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix64k_00000
{
    constexpr const auto addr = 0x00000250U;
    constexpr const auto name = "ia32_mtrr_fix64k_00000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix16k_80000
{
    constexpr const auto addr = 0x00000258U;
    constexpr const auto name = "ia32_mtrr_fix16k_80000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix16k_A0000
{
    constexpr const auto addr = 0x00000259U;
    constexpr const auto name = "ia32_mtrr_fix16k_A0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_C0000
{
    constexpr const auto addr = 0x00000268U;
    constexpr const auto name = "ia32_mtrr_fix4k_C0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_C8000
{
    constexpr const auto addr = 0x00000269U;
    constexpr const auto name = "ia32_mtrr_fix4k_C8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_D0000
{
    constexpr const auto addr = 0x0000026AU;
    constexpr const auto name = "ia32_mtrr_fix4k_D0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_D8000
{
    constexpr const auto addr = 0x0000026BU;
    constexpr const auto name = "ia32_mtrr_fix4k_D8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_E0000
{
    constexpr const auto addr = 0x0000026CU;
    constexpr const auto name = "ia32_mtrr_fix4k_E0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_E8000
{
    constexpr const auto addr = 0x0000026DU;
    constexpr const auto name = "ia32_mtrr_fix4k_E8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_F0000
{
    constexpr const auto addr = 0x0000026EU;
    constexpr const auto name = "ia32_mtrr_fix4k_F0000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mtrr_fix4k_F8000
{
    constexpr const auto addr = 0x0000026FU;
    constexpr const auto name = "ia32_mtrr_fix4k_F8000";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc0_ctl2
{
    constexpr const auto addr = 0x00000280U;
    constexpr const auto name = "ia32_mc0_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc1_ctl2
{
    constexpr const auto addr = 0x00000281U;
    constexpr const auto name = "ia32_mc1_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc2_ctl2
{
    constexpr const auto addr = 0x00000282U;
    constexpr const auto name = "ia32_mc2_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc3_ctl2
{
    constexpr const auto addr = 0x00000283U;
    constexpr const auto name = "ia32_mc3_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc4_ctl2
{
    constexpr const auto addr = 0x00000284U;
    constexpr const auto name = "ia32_mc4_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc5_ctl2
{
    constexpr const auto addr = 0x00000285U;
    constexpr const auto name = "ia32_mc5_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc6_ctl2
{
    constexpr const auto addr = 0x00000286U;
    constexpr const auto name = "ia32_mc6_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc7_ctl2
{
    constexpr const auto addr = 0x00000287U;
    constexpr const auto name = "ia32_mc7_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc8_ctl2
{
    constexpr const auto addr = 0x00000288U;
    constexpr const auto name = "ia32_mc8_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc9_ctl2
{
    constexpr const auto addr = 0x00000289U;
    constexpr const auto name = "ia32_mc9_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc10_ctl2
{
    constexpr const auto addr = 0x0000028AU;
    constexpr const auto name = "ia32_mc10_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc11_ctl2
{
    constexpr const auto addr = 0x0000028BU;
    constexpr const auto name = "ia32_mc11_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc12_ctl2
{
    constexpr const auto addr = 0x0000028CU;
    constexpr const auto name = "ia32_mc12_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc13_ctl2
{
    constexpr const auto addr = 0x0000028DU;
    constexpr const auto name = "ia32_mc13_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc14_ctl2
{
    constexpr const auto addr = 0x0000028EU;
    constexpr const auto name = "ia32_mc14_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc15_ctl2
{
    constexpr const auto addr = 0x0000028FU;
    constexpr const auto name = "ia32_mc15_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc16_ctl2
{
    constexpr const auto addr = 0x00000290U;
    constexpr const auto name = "ia32_mc16_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc17_ctl2
{
    constexpr const auto addr = 0x00000291U;
    constexpr const auto name = "ia32_mc17_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc18_ctl2
{
    constexpr const auto addr = 0x00000292U;
    constexpr const auto name = "ia32_mc18_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc19_ctl2
{
    constexpr const auto addr = 0x00000293U;
    constexpr const auto name = "ia32_mc19_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc20_ctl2
{
    constexpr const auto addr = 0x00000294U;
    constexpr const auto name = "ia32_mc20_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc21_ctl2
{
    constexpr const auto addr = 0x00000295U;
    constexpr const auto name = "ia32_mc21_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc22_ctl2
{
    constexpr const auto addr = 0x00000296U;
    constexpr const auto name = "ia32_mc22_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc23_ctl2
{
    constexpr const auto addr = 0x00000297U;
    constexpr const auto name = "ia32_mc23_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc24_ctl2
{
    constexpr const auto addr = 0x00000298U;
    constexpr const auto name = "ia32_mc24_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc25_ctl2
{
    constexpr const auto addr = 0x00000299U;
    constexpr const auto name = "ia32_mc25_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc26_ctl2
{
    constexpr const auto addr = 0x0000029AU;
    constexpr const auto name = "ia32_mc26_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc27_ctl2
{
    constexpr const auto addr = 0x0000029BU;
    constexpr const auto name = "ia32_mc27_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc28_ctl2
{
    constexpr const auto addr = 0x0000029CU;
    constexpr const auto name = "ia32_mc28_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc29_ctl2
{
    constexpr const auto addr = 0x0000029DU;
    constexpr const auto name = "ia32_mc29_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc30_ctl2
{
    constexpr const auto addr = 0x0000029EU;
    constexpr const auto name = "ia32_mc30_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mc31_ctl2
{
    constexpr const auto addr = 0x0000029FU;
    constexpr const auto name = "ia32_mc31_ctl2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace error_threshold
    {
        constexpr const auto mask = 0x0000000000007FFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "error_threshold";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cmci_en
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cmci_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        error_threshold::dump(level);
        cmci_en::dump(level);
    }
}

namespace ia32_mtrr_def_type
{
    constexpr const auto addr = 0x000002FFU;
    constexpr const auto name = "ia32_mtrr_def_type";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace def_mem_type
    {
        constexpr const auto mask = 0x0000000000000007ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "def_mem_type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace fixed_range_mtrr
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "fixed_range_mtrr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mtrr
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "mtrr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        def_mem_type::dump(level);
        fixed_range_mtrr::dump(level);
        mtrr::dump(level);
    }
}

namespace ia32_fixed_ctr0
{
    constexpr const auto addr = 0x00000309U;
    constexpr const auto name = "ia32_fixed_ctr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_fixed_ctr1
{
    constexpr const auto addr = 0x0000030AU;
    constexpr const auto name = "ia32_fixed_ctr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_fixed_ctr2
{
    constexpr const auto addr = 0x0000030BU;
    constexpr const auto name = "ia32_fixed_ctr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_perf_capabilities
{
    constexpr const auto addr = 0x00000345U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace pebs_trap
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "pebs_trap";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pebs_savearchregs
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "pebs_savearchregs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pebs_record_format
    {
        constexpr const auto mask = 0x0000000000000F00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "pebs_record_format";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace freeze
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "freeze";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace counter_width
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "counter_width";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        lbo_format::dump(level);
        pebs_trap::dump(level);
        pebs_savearchregs::dump(level);
        pebs_record_format::dump(level);
        freeze::dump(level);
        counter_width::dump(level);
    }
}

namespace ia32_fixed_ctr_ctrl
{
    constexpr const auto addr = 0x0000038DU;
    constexpr const auto name = "ia32_fixed_ctr_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace en0_os
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "en0_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en0_usr
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "en0_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en0_anythread
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "en0_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en0_pmi
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "en0_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en1_os
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "en1_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en1_usr
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "en1_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en1_anythread
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "en1_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en1_pmi
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "en1_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en2_os
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "en2_os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en2_usr
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "en2_usr";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en2_anythread
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "en2_anythread";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace en2_pmi
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "en2_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        en0_os::dump(level);
        en0_usr::dump(level);
        en0_anythread::dump(level);
        en0_pmi::dump(level);
        en1_os::dump(level);
        en1_usr::dump(level);
        en1_anythread::dump(level);
        en1_pmi::dump(level);
        en2_os::dump(level);
        en2_usr::dump(level);
        en2_anythread::dump(level);
        en2_pmi::dump(level);
    }
}

namespace ia32_perf_global_status
{
    constexpr const auto addr = 0x0000038EU;
    constexpr const auto name = "ia32_perf_global_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_pmc3
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "ovf_pmc3";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixedctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "ovf_fixedctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixedctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33;
        constexpr const auto name = "ovf_fixedctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixedctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "ovf_fixedctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55;
        constexpr const auto name = "trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace asci
    {
        constexpr const auto mask = 0x1000000000000000ULL;
        constexpr const auto from = 60;
        constexpr const auto name = "asci";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61;
        constexpr const auto name = "ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62;
        constexpr const auto name = "ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace condchgd
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63;
        constexpr const auto name = "condchgd";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        ovf_pmc0::dump(level);
        ovf_pmc1::dump(level);
        ovf_pmc2::dump(level);
        ovf_pmc3::dump(level);
        ovf_fixedctr0::dump(level);
        ovf_fixedctr1::dump(level);
        ovf_fixedctr2::dump(level);
        trace_topa_pmi::dump(level);
        lbr_frz::dump(level);
        ctr_frz::dump(level);
        asci::dump(level);
        ovf_uncore::dump(level);
        ovfbuf::dump(level);
        condchgd::dump(level);
    }
}

namespace ia32_perf_global_ctrl
{
    constexpr const auto addr = 0x0000038FU;
    constexpr const auto name = "ia32_perf_global_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc3
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pmc3";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc4
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pmc4";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc5
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "pmc5";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc6
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "pmc6";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmc7
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "pmc7";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33;
        constexpr const auto name = "fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        pmc0::dump(level);
        pmc1::dump(level);
        pmc2::dump(level);
        pmc3::dump(level);
        pmc4::dump(level);
        pmc5::dump(level);
        pmc6::dump(level);
        pmc7::dump(level);
        fixed_ctr0::dump(level);
        fixed_ctr1::dump(level);
        fixed_ctr2::dump(level);
    }
}

namespace ia32_perf_global_ovf_ctrl
{
    constexpr const auto addr = 0x00000390U;
    constexpr const auto name = "ia32_perf_global_ovf_ctrl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace clear_ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "clear_ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "clear_ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "clear_ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "clear_ovf_fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33;
        constexpr const auto name = "clear_ovf_fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "clear_ovf_fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55;
        constexpr const auto name = "clear_trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61;
        constexpr const auto name = "clear_ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62;
        constexpr const auto name = "clear_ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_condchgd
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63;
        constexpr const auto name = "clear_condchgd";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        clear_ovf_pmc0::dump(level);
        clear_ovf_pmc1::dump(level);
        clear_ovf_pmc2::dump(level);
        clear_ovf_fixed_ctr0::dump(level);
        clear_ovf_fixed_ctr1::dump(level);
        clear_ovf_fixed_ctr2::dump(level);
        clear_trace_topa_pmi::dump(level);
        lbr_frz::dump(level);
        ctr_frz::dump(level);
        clear_ovf_uncore::dump(level);
        clear_ovfbuf::dump(level);
        clear_condchgd::dump(level);
    }
}

namespace ia32_perf_global_status_set
{
    constexpr const auto addr = 0x00000391U;
    constexpr const auto name = "ia32_perf_global_status_set";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace ovf_pmc0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "ovf_pmc0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_pmc1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "ovf_pmc1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_pmc2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "ovf_pmc2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "ovf_fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33;
        constexpr const auto name = "ovf_fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "ovf_fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace trace_topa_pmi
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55;
        constexpr const auto name = "trace_topa_pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lbr_frz
    {
        constexpr const auto mask = 0x0400000000000000ULL;
        constexpr const auto from = 58;
        constexpr const auto name = "lbr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ctr_frz
    {
        constexpr const auto mask = 0x0800000000000000ULL;
        constexpr const auto from = 59;
        constexpr const auto name = "ctr_frz";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovf_uncore
    {
        constexpr const auto mask = 0x2000000000000000ULL;
        constexpr const auto from = 61;
        constexpr const auto name = "ovf_uncore";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ovfbuf
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62;
        constexpr const auto name = "clear_ovfbuf";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        ovf_pmc0::dump(level);
        ovf_pmc1::dump(level);
        ovf_pmc2::dump(level);
        ovf_fixed_ctr0::dump(level);
        ovf_fixed_ctr1::dump(level);
        ovf_fixed_ctr2::dump(level);
        trace_topa_pmi::dump(level);
        lbr_frz::dump(level);
        ctr_frz::dump(level);
        ovf_uncore::dump(level);
        ovfbuf::dump(level);
    }
}

namespace ia32_perf_global_inuse
{
    constexpr const auto addr = 0x00000392U;
    constexpr const auto name = "ia32_perf_global_inuse";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace perfevtsel0
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "perfevtsel0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace perfevtsel1
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "perfevtsel1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace perfevtsel2
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "perfevtsel2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr0
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "fixed_ctr0";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr1
    {
        constexpr const auto mask = 0x0000000200000000ULL;
        constexpr const auto from = 33;
        constexpr const auto name = "fixed_ctr1";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fixed_ctr2
    {
        constexpr const auto mask = 0x0000000400000000ULL;
        constexpr const auto from = 34;
        constexpr const auto name = "fixed_ctr2";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pmi
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63;
        constexpr const auto name = "pmi";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        perfevtsel0::dump(level);
        perfevtsel1::dump(level);
        perfevtsel2::dump(level);
        fixed_ctr0::dump(level);
        fixed_ctr1::dump(level);
        fixed_ctr2::dump(level);
        pmi::dump(level);
    }
}

namespace ia32_pebs_enable
{
    constexpr const auto addr = 0x000003F1U;
    constexpr const auto name = "ia32_pebs_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace pebs
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "pebs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        pebs::dump(level);
    }
}

namespace ia32_mc6_ctl
{
    constexpr const auto addr = 0x00000418U;
    constexpr const auto name = "ia32_mc6_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc6_status
{
    constexpr const auto addr = 0x00000419U;
    constexpr const auto name = "ia32_mc6_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc6_addr
{
    constexpr const auto addr = 0x0000041AU;
    constexpr const auto name = "ia32_mc6_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc6_misc
{
    constexpr const auto addr = 0x0000041BU;
    constexpr const auto name = "ia32_mc6_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc7_ctl
{
    constexpr const auto addr = 0x0000041CU;
    constexpr const auto name = "ia32_mc7_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc7_status
{
    constexpr const auto addr = 0x0000041DU;
    constexpr const auto name = "ia32_mc7_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc7_addr
{
    constexpr const auto addr = 0x0000041EU;
    constexpr const auto name = "ia32_mc7_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc7_misc
{
    constexpr const auto addr = 0x0000041FU;
    constexpr const auto name = "ia32_mc7_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc8_ctl
{
    constexpr const auto addr = 0x00000420U;
    constexpr const auto name = "ia32_mc8_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc8_status
{
    constexpr const auto addr = 0x00000421U;
    constexpr const auto name = "ia32_mc8_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc8_addr
{
    constexpr const auto addr = 0x00000422U;
    constexpr const auto name = "ia32_mc8_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc8_misc
{
    constexpr const auto addr = 0x00000423U;
    constexpr const auto name = "ia32_mc8_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc9_ctl
{
    constexpr const auto addr = 0x00000424U;
    constexpr const auto name = "ia32_mc9_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc9_status
{
    constexpr const auto addr = 0x00000425U;
    constexpr const auto name = "ia32_mc9_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc9_addr
{
    constexpr const auto addr = 0x00000426U;
    constexpr const auto name = "ia32_mc9_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc9_misc
{
    constexpr const auto addr = 0x00000427U;
    constexpr const auto name = "ia32_mc9_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc10_ctl
{
    constexpr const auto addr = 0x00000428U;
    constexpr const auto name = "ia32_mc10_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc10_status
{
    constexpr const auto addr = 0x00000429U;
    constexpr const auto name = "ia32_mc10_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc10_addr
{
    constexpr const auto addr = 0x0000042AU;
    constexpr const auto name = "ia32_mc10_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc10_misc
{
    constexpr const auto addr = 0x0000042BU;
    constexpr const auto name = "ia32_mc10_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc11_ctl
{
    constexpr const auto addr = 0x0000042CU;
    constexpr const auto name = "ia32_mc11_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc11_status
{
    constexpr const auto addr = 0x0000042DU;
    constexpr const auto name = "ia32_mc11_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc11_addr
{
    constexpr const auto addr = 0x0000042EU;
    constexpr const auto name = "ia32_mc11_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc11_misc
{
    constexpr const auto addr = 0x0000042FU;
    constexpr const auto name = "ia32_mc11_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc12_ctl
{
    constexpr const auto addr = 0x00000430U;
    constexpr const auto name = "ia32_mc12_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc12_status
{
    constexpr const auto addr = 0x00000431U;
    constexpr const auto name = "ia32_mc12_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc12_addr
{
    constexpr const auto addr = 0x00000432U;
    constexpr const auto name = "ia32_mc12_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc12_misc
{
    constexpr const auto addr = 0x00000433U;
    constexpr const auto name = "ia32_mc12_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc13_ctl
{
    constexpr const auto addr = 0x00000434U;
    constexpr const auto name = "ia32_mc13_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc13_status
{
    constexpr const auto addr = 0x00000435U;
    constexpr const auto name = "ia32_mc13_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc13_addr
{
    constexpr const auto addr = 0x00000436U;
    constexpr const auto name = "ia32_mc13_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc13_misc
{
    constexpr const auto addr = 0x00000437U;
    constexpr const auto name = "ia32_mc13_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc14_ctl
{
    constexpr const auto addr = 0x00000438U;
    constexpr const auto name = "ia32_mc14_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc14_status
{
    constexpr const auto addr = 0x00000439U;
    constexpr const auto name = "ia32_mc14_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc14_addr
{
    constexpr const auto addr = 0x0000043AU;
    constexpr const auto name = "ia32_mc14_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc14_misc
{
    constexpr const auto addr = 0x0000043BU;
    constexpr const auto name = "ia32_mc14_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc15_ctl
{
    constexpr const auto addr = 0x0000043CU;
    constexpr const auto name = "ia32_mc15_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc15_status
{
    constexpr const auto addr = 0x0000043DU;
    constexpr const auto name = "ia32_mc15_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc15_addr
{
    constexpr const auto addr = 0x0000043EU;
    constexpr const auto name = "ia32_mc15_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc15_misc
{
    constexpr const auto addr = 0x0000043FU;
    constexpr const auto name = "ia32_mc15_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc16_ctl
{
    constexpr const auto addr = 0x00000440U;
    constexpr const auto name = "ia32_mc16_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc16_status
{
    constexpr const auto addr = 0x00000441U;
    constexpr const auto name = "ia32_mc16_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc16_addr
{
    constexpr const auto addr = 0x00000442U;
    constexpr const auto name = "ia32_mc16_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc16_misc
{
    constexpr const auto addr = 0x00000443U;
    constexpr const auto name = "ia32_mc16_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc17_ctl
{
    constexpr const auto addr = 0x00000444U;
    constexpr const auto name = "ia32_mc17_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc17_status
{
    constexpr const auto addr = 0x00000445U;
    constexpr const auto name = "ia32_mc17_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc17_addr
{
    constexpr const auto addr = 0x00000446U;
    constexpr const auto name = "ia32_mc17_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc17_misc
{
    constexpr const auto addr = 0x00000447U;
    constexpr const auto name = "ia32_mc17_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc18_ctl
{
    constexpr const auto addr = 0x00000448U;
    constexpr const auto name = "ia32_mc18_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc18_status
{
    constexpr const auto addr = 0x00000449U;
    constexpr const auto name = "ia32_mc18_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc18_addr
{
    constexpr const auto addr = 0x0000044AU;
    constexpr const auto name = "ia32_mc18_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc18_misc
{
    constexpr const auto addr = 0x0000044BU;
    constexpr const auto name = "ia32_mc18_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc19_ctl
{
    constexpr const auto addr = 0x0000044CU;
    constexpr const auto name = "ia32_mc19_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc19_status
{
    constexpr const auto addr = 0x0000044DU;
    constexpr const auto name = "ia32_mc19_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc19_addr
{
    constexpr const auto addr = 0x0000044EU;
    constexpr const auto name = "ia32_mc19_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc19_misc
{
    constexpr const auto addr = 0x0000044FU;
    constexpr const auto name = "ia32_mc19_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc20_ctl
{
    constexpr const auto addr = 0x00000450U;
    constexpr const auto name = "ia32_mc20_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc20_status
{
    constexpr const auto addr = 0x00000451U;
    constexpr const auto name = "ia32_mc20_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc20_addr
{
    constexpr const auto addr = 0x00000452U;
    constexpr const auto name = "ia32_mc20_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc20_misc
{
    constexpr const auto addr = 0x00000453U;
    constexpr const auto name = "ia32_mc20_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc21_ctl
{
    constexpr const auto addr = 0x00000454U;
    constexpr const auto name = "ia32_mc21_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc21_status
{
    constexpr const auto addr = 0x00000455U;
    constexpr const auto name = "ia32_mc21_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc21_addr
{
    constexpr const auto addr = 0x00000456U;
    constexpr const auto name = "ia32_mc21_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc21_misc
{
    constexpr const auto addr = 0x00000457U;
    constexpr const auto name = "ia32_mc21_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc22_ctl
{
    constexpr const auto addr = 0x00000458U;
    constexpr const auto name = "ia32_mc22_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc22_status
{
    constexpr const auto addr = 0x00000459U;
    constexpr const auto name = "ia32_mc22_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc22_addr
{
    constexpr const auto addr = 0x0000045AU;
    constexpr const auto name = "ia32_mc22_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc22_misc
{
    constexpr const auto addr = 0x0000045BU;
    constexpr const auto name = "ia32_mc22_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc23_ctl
{
    constexpr const auto addr = 0x0000045CU;
    constexpr const auto name = "ia32_mc23_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc23_status
{
    constexpr const auto addr = 0x0000045DU;
    constexpr const auto name = "ia32_mc23_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc23_addr
{
    constexpr const auto addr = 0x0000045EU;
    constexpr const auto name = "ia32_mc23_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc23_misc
{
    constexpr const auto addr = 0x0000045FU;
    constexpr const auto name = "ia32_mc23_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc24_ctl
{
    constexpr const auto addr = 0x00000460U;
    constexpr const auto name = "ia32_mc24_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc24_status
{
    constexpr const auto addr = 0x00000461U;
    constexpr const auto name = "ia32_mc24_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc24_addr
{
    constexpr const auto addr = 0x00000462U;
    constexpr const auto name = "ia32_mc24_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc24_misc
{
    constexpr const auto addr = 0x00000463U;
    constexpr const auto name = "ia32_mc24_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc25_ctl
{
    constexpr const auto addr = 0x00000464U;
    constexpr const auto name = "ia32_mc25_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc25_status
{
    constexpr const auto addr = 0x00000465U;
    constexpr const auto name = "ia32_mc25_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc25_addr
{
    constexpr const auto addr = 0x00000466U;
    constexpr const auto name = "ia32_mc25_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc25_misc
{
    constexpr const auto addr = 0x00000467U;
    constexpr const auto name = "ia32_mc25_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc26_ctl
{
    constexpr const auto addr = 0x00000468U;
    constexpr const auto name = "ia32_mc26_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc26_status
{
    constexpr const auto addr = 0x00000469U;
    constexpr const auto name = "ia32_mc26_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc26_addr
{
    constexpr const auto addr = 0x0000046AU;
    constexpr const auto name = "ia32_mc26_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc26_misc
{
    constexpr const auto addr = 0x0000046BU;
    constexpr const auto name = "ia32_mc26_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc27_ctl
{
    constexpr const auto addr = 0x0000046CU;
    constexpr const auto name = "ia32_mc27_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc27_status
{
    constexpr const auto addr = 0x0000046DU;
    constexpr const auto name = "ia32_mc27_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc27_addr
{
    constexpr const auto addr = 0x0000046EU;
    constexpr const auto name = "ia32_mc27_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc27_misc
{
    constexpr const auto addr = 0x0000046FU;
    constexpr const auto name = "ia32_mc27_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc28_ctl
{
    constexpr const auto addr = 0x00000470U;
    constexpr const auto name = "ia32_mc28_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc28_status
{
    constexpr const auto addr = 0x00000471U;
    constexpr const auto name = "ia32_mc28_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc28_addr
{
    constexpr const auto addr = 0x00000472U;
    constexpr const auto name = "ia32_mc28_addr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mc28_misc
{
    constexpr const auto addr = 0x00000473U;
    constexpr const auto name = "ia32_mc28_misc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_vmx_basic
{
    constexpr const auto addr = 0x00000480U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace vmxon_vmcs_region_size
    {
        constexpr const auto mask = 0x00001FFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "vmxon_vmcs_region_size";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace physical_address_width
    {
        constexpr const auto mask = 0x0001000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "physical_address_width";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace dual_monitor_mode_support
    {
        constexpr const auto mask = 0x0002000000000000ULL;
        constexpr const auto from = 49;
        constexpr const auto name = "dual_monitor_mode_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace memory_type
    {
        constexpr const auto mask = 0x003C000000000000ULL;
        constexpr const auto from = 50;
        constexpr const auto name = "memory_type";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace ins_outs_exit_information
    {
        constexpr const auto mask = 0x0040000000000000ULL;
        constexpr const auto from = 54;
        constexpr const auto name = "ins_outs_exit_information";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace true_based_controls
    {
        constexpr const auto mask = 0x0080000000000000ULL;
        constexpr const auto from = 55;
        constexpr const auto name = "true_based_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        revision_id::dump(level);
        vmxon_vmcs_region_size::dump(level);
        physical_address_width::dump(level);
        dual_monitor_mode_support::dump(level);
        memory_type::dump(level);
        ins_outs_exit_information::dump(level);
        true_based_controls::dump(level);
    }
}

namespace ia32_vmx_pinbased_ctls
{
    constexpr const auto addr = 0x00000481U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        allowed_0_settings::dump(level);
        allowed_1_settings::dump(level);
    }
}

namespace ia32_vmx_procbased_ctls
{
    constexpr const auto addr = 0x00000482U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        allowed_0_settings::dump(level);
        allowed_1_settings::dump(level);
    }
}

namespace ia32_vmx_exit_ctls
{
    constexpr const auto addr = 0x00000483U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        allowed_0_settings::dump(level);
        allowed_1_settings::dump(level);
    }
}

namespace ia32_vmx_entry_ctls
{
    constexpr const auto addr = 0x00000484U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace allowed_1_settings
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "allowed_1_settings";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        allowed_0_settings::dump(level);
        allowed_1_settings::dump(level);
    }
}

namespace ia32_vmx_misc
{
    constexpr const auto addr = 0x00000485U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace store_efer_lma_on_vm_exit
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "store_efer_lma_on_vm_exit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace activity_state_hlt_support
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "activity_state_hlt_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace activity_state_shutdown_support
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "activity_state_shutdown_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace activity_state_wait_for_sipi_support
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "activity_state_wait_for_sipi_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace processor_trace_support
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "processor_trace_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rdmsr_in_smm_support
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "rdmsr_in_smm_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr3_targets
    {
        constexpr const auto mask = 0x0000000001FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "cr3_targets";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace max_num_msr_load_store_on_exit
    {
        constexpr const auto mask = 0x000000000E000000ULL;
        constexpr const auto from = 25;
        constexpr const auto name = "max_num_msr_load_store_on_exit";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace vmxoff_blocked_smi_support
    {
        constexpr const auto mask = 0x0000000010000000ULL;
        constexpr const auto from = 28;
        constexpr const auto name = "vmxoff_blocked_smi_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace vmwrite_all_fields_support
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29;
        constexpr const auto name = "vmwrite_all_fields_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace injection_with_instruction_length_of_zero
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "injection_with_instruction_length_of_zero";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        preemption_timer_decrement::dump(level);
        store_efer_lma_on_vm_exit::dump(level);
        activity_state_hlt_support::dump(level);
        activity_state_shutdown_support::dump(level);
        activity_state_wait_for_sipi_support::dump(level);
        processor_trace_support::dump(level);
        rdmsr_in_smm_support::dump(level);
        cr3_targets::dump(level);
        max_num_msr_load_store_on_exit::dump(level);
        vmxoff_blocked_smi_support::dump(level);
        vmwrite_all_fields_support::dump(level);
        injection_with_instruction_length_of_zero::dump(level);
    }
}

namespace ia32_vmx_cr0_fixed0
{
    constexpr const auto addr = 0x00000486U;
    constexpr const auto name = "ia32_vmx_cr0_fixed0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_vmx_cr0_fixed1
{
    constexpr const auto addr = 0x00000487U;
    constexpr const auto name = "ia32_vmx_cr0_fixed1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_vmx_cr4_fixed0
{
    constexpr const auto addr = 0x00000488U;
    constexpr const auto name = "ia32_vmx_cr4_fixed0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_vmx_cr4_fixed1
{
    constexpr const auto addr = 0x00000489U;
    constexpr const auto name = "ia32_vmx_cr4_fixed1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_vmx_vmcs_enum
{
    constexpr const auto addr = 0x0000048AU;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        highest_index::dump(level);
    }
}

namespace ia32_vmx_procbased_ctls2
{
    constexpr const auto addr = 0x0000048BU;
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_ept
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "enable_ept";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace descriptor_table_exiting
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "descriptor_table_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_rdtscp
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "enable_rdtscp";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace virtualize_x2apic_mode
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "virtualize_x2apic_mode";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_vpid
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "enable_vpid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace wbinvd_exiting
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "wbinvd_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace unrestricted_guest
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "unrestricted_guest";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace apic_register_virtualization
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "apic_register_virtualization";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace virtual_interrupt_delivery
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "virtual_interrupt_delivery";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pause_loop_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "pause_loop_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rdrand_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdrand_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_invpcid
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "enable_invpcid";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_vm_functions
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_vm_functions";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace vmcs_shadowing
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "vmcs_shadowing";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_encls_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "enable_encls_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rdseed_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "rdseed_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_pml
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "enable_pml";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ept_violation_ve
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "ept_violation_ve";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pt_conceal_nonroot_operation
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19;
        constexpr const auto name = "pt_conceal_nonroot_operation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace enable_xsaves_xrstors
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "enable_xsaves_xrstors";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ept_mode_based_control
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "ept_mode_based_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace use_tsc_scaling
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25;
        constexpr const auto name = "use_tsc_scaling";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtualize_apic_accesses::dump(level);
        enable_ept::dump(level);
        descriptor_table_exiting::dump(level);
        enable_rdtscp::dump(level);
        virtualize_x2apic_mode::dump(level);
        enable_vpid::dump(level);
        wbinvd_exiting::dump(level);
        unrestricted_guest::dump(level);
        apic_register_virtualization::dump(level);
        virtual_interrupt_delivery::dump(level);
        pause_loop_exiting::dump(level);
        rdrand_exiting::dump(level);
        enable_invpcid::dump(level);
        enable_vm_functions::dump(level);
        vmcs_shadowing::dump(level);
        enable_encls_exiting::dump(level);
        rdseed_exiting::dump(level);
        enable_pml::dump(level);
        ept_violation_ve::dump(level);
        pt_conceal_nonroot_operation::dump(level);
        enable_xsaves_xrstors::dump(level);
        ept_mode_based_control::dump(level);
        use_tsc_scaling::dump(level);
    }
}

namespace ia32_vmx_ept_vpid_cap
{
    constexpr const auto addr = 0x0000048CU;
    constexpr const auto name = "ia32_vmx_ept_vpid_cap";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace execute_only_translation
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "execute_only_translation";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace page_walk_length_of_4
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "page_walk_length_of_4";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace memory_type_uncacheable_supported
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "memory_type_uncacheable_supported";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace memory_type_write_back_supported
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "memory_type_write_back_supported";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pde_2mb_support
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "pde_2mb_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pdpte_1gb_support
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "pdpte_1gb_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invept_support
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "invept_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace accessed_dirty_support
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "accessed_dirty_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invept_single_context_support
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25;
        constexpr const auto name = "invept_single_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invept_all_context_support
    {
        constexpr const auto mask = 0x0000000004000000ULL;
        constexpr const auto from = 26;
        constexpr const auto name = "invept_all_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invvpid_support
    {
        constexpr const auto mask = 0x0000000100000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "invvpid_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invvpid_individual_address_support
    {
        constexpr const auto mask = 0x0000010000000000ULL;
        constexpr const auto from = 40;
        constexpr const auto name = "invvpid_individual_address_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invvpid_single_context_support
    {
        constexpr const auto mask = 0x0000020000000000ULL;
        constexpr const auto from = 41;
        constexpr const auto name = "invvpid_single_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invvpid_all_context_support
    {
        constexpr const auto mask = 0x0000040000000000ULL;
        constexpr const auto from = 42;
        constexpr const auto name = "invvpid_all_context_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invvpid_single_context_retaining_globals_support
    {
        constexpr const auto mask = 0x0000080000000000ULL;
        constexpr const auto from = 43;
        constexpr const auto name = "invvpid_single_context_retaining_globals_support";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        execute_only_translation::dump(level);
        page_walk_length_of_4::dump(level);
        memory_type_uncacheable_supported::dump(level);
        memory_type_write_back_supported::dump(level);
        pde_2mb_support::dump(level);
        pdpte_1gb_support::dump(level);
        invept_support::dump(level);
        accessed_dirty_support::dump(level);
        invept_single_context_support::dump(level);
        invept_all_context_support::dump(level);
        invvpid_support::dump(level);
        invvpid_individual_address_support::dump(level);
        invvpid_single_context_support::dump(level);
        invvpid_all_context_support::dump(level);
        invvpid_single_context_retaining_globals_support::dump(level);
    }
}

namespace ia32_vmx_true_pinbased_ctls
{
    constexpr const auto addr = 0x0000048DU;
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace nmi_exiting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "nmi_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace virtual_nmis
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "virtual_nmis";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace activate_vmx_preemption_timer
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "activate_vmx_preemption_timer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace process_posted_interrupts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "process_posted_interrupts";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        external_interrupt_exiting::dump(level);
        nmi_exiting::dump(level);
        virtual_nmis::dump(level);
        activate_vmx_preemption_timer::dump(level);
        process_posted_interrupts::dump(level);
    }
}

namespace ia32_vmx_true_procbased_ctls
{
    constexpr const auto addr = 0x0000048EU;
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace use_tsc_offsetting
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "use_tsc_offsetting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace hlt_exiting
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "hlt_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace invlpg_exiting
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "invlpg_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mwait_exiting
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "mwait_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rdpmc_exiting
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "rdpmc_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace rdtsc_exiting
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "rdtsc_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr3_load_exiting
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "cr3_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr3_store_exiting
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "cr3_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr8_load_exiting
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19;
        constexpr const auto name = "cr8_load_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr8_store_exiting
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "cr8_store_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace use_tpr_shadow
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "use_tpr_shadow";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace nmi_window_exiting
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "nmi_window_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mov_dr_exiting
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "mov_dr_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace unconditional_io_exiting
    {
        constexpr const auto mask = 0x0000000001000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "unconditional_io_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace use_io_bitmaps
    {
        constexpr const auto mask = 0x0000000002000000ULL;
        constexpr const auto from = 25;
        constexpr const auto name = "use_io_bitmaps";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace monitor_trap_flag
    {
        constexpr const auto mask = 0x0000000008000000ULL;
        constexpr const auto from = 27;
        constexpr const auto name = "monitor_trap_flag";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace use_msr_bitmap
    {
        constexpr const auto mask = 0x0000000010000000ULL;
        constexpr const auto from = 28;
        constexpr const auto name = "use_msr_bitmap";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace monitor_exiting
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29;
        constexpr const auto name = "monitor_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pause_exiting
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "pause_exiting";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace activate_secondary_controls
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31;
        constexpr const auto name = "activate_secondary_controls";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        interrupt_window_exiting::dump(level);
        use_tsc_offsetting::dump(level);
        hlt_exiting::dump(level);
        invlpg_exiting::dump(level);
        mwait_exiting::dump(level);
        rdpmc_exiting::dump(level);
        rdtsc_exiting::dump(level);
        cr3_load_exiting::dump(level);
        cr3_store_exiting::dump(level);
        cr8_load_exiting::dump(level);
        cr8_store_exiting::dump(level);
        use_tpr_shadow::dump(level);
        nmi_window_exiting::dump(level);
        mov_dr_exiting::dump(level);
        unconditional_io_exiting::dump(level);
        use_io_bitmaps::dump(level);
        monitor_trap_flag::dump(level);
        use_msr_bitmap::dump(level);
        monitor_exiting::dump(level);
        pause_exiting::dump(level);
        activate_secondary_controls::dump(level);
    }
}

namespace ia32_vmx_true_exit_ctls
{
    constexpr const auto addr = 0x0000048FU;
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace host_address_space_size
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "host_address_space_size";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace acknowledge_interrupt_on_exit
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "acknowledge_interrupt_on_exit";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace save_ia32_pat
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "save_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000080000ULL;
        constexpr const auto from = 19;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace save_ia32_efer
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "save_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace save_vmx_preemption_timer_value
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "save_vmx_preemption_timer_value";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace clear_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000800000ULL;
        constexpr const auto from = 23;
        constexpr const auto name = "clear_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        save_debug_controls::dump(level);
        host_address_space_size::dump(level);
        load_ia32_perf_global_ctrl::dump(level);
        acknowledge_interrupt_on_exit::dump(level);
        save_ia32_pat::dump(level);
        load_ia32_pat::dump(level);
        save_ia32_efer::dump(level);
        load_ia32_efer::dump(level);
        save_vmx_preemption_timer_value::dump(level);
        clear_ia32_bndcfgs::dump(level);
    }
}

namespace ia32_vmx_true_entry_ctls
{
    constexpr const auto addr = 0x00000490U;
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

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace ia_32e_mode_guest
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "ia_32e_mode_guest";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace entry_to_smm
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "entry_to_smm";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace deactivate_dual_monitor_treatment
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "deactivate_dual_monitor_treatment";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_perf_global_ctrl
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "load_ia32_perf_global_ctrl";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_pat
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "load_ia32_pat";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_efer
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "load_ia32_efer";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace load_ia32_bndcfgs
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "load_ia32_bndcfgs";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline auto is_allowed0() noexcept
        { return (_read_msr(addr) & mask) == 0; }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        load_debug_controls::dump(level);
        ia_32e_mode_guest::dump(level);
        entry_to_smm::dump(level);
        deactivate_dual_monitor_treatment::dump(level);
        load_ia32_perf_global_ctrl::dump(level);
        load_ia32_pat::dump(level);
        load_ia32_efer::dump(level);
        load_ia32_bndcfgs::dump(level);
    }
}

namespace ia32_vmx_vmfunc
{
    constexpr const auto addr = 0x00000491U;
    constexpr const auto name = "ia32_vmx_vmfunc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace eptp_switching
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "eptp_switching";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_allowed1() noexcept
        { return (_read_msr(addr) & (mask << 32)) != 0; }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        eptp_switching::dump(level);
    }
}

namespace ia32_a_pmc0
{
    constexpr const auto addr = 0x000004C1U;
    constexpr const auto name = "ia32_a_pmc0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc1
{
    constexpr const auto addr = 0x000004C2U;
    constexpr const auto name = "ia32_a_pmc1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc2
{
    constexpr const auto addr = 0x000004C3U;
    constexpr const auto name = "ia32_a_pmc2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc3
{
    constexpr const auto addr = 0x000004C4U;
    constexpr const auto name = "ia32_a_pmc3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc4
{
    constexpr const auto addr = 0x000004C5U;
    constexpr const auto name = "ia32_a_pmc4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc5
{
    constexpr const auto addr = 0x000004C6U;
    constexpr const auto name = "ia32_a_pmc5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc6
{
    constexpr const auto addr = 0x000004C7U;
    constexpr const auto name = "ia32_a_pmc6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_a_pmc7
{
    constexpr const auto addr = 0x000004C8U;
    constexpr const auto name = "ia32_a_pmc7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_mcg_ext_ctl
{
    constexpr const auto addr = 0x000004D0U;
    constexpr const auto name = "ia32_mcg_ext_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace lmce_en
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "lmce_en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        lmce_en::dump(level);
    }
}

namespace ia32_sgx_svn_sinit
{
    constexpr const auto addr = 0x00000500U;
    constexpr const auto name = "ia32_sgx_svn_sinit";

    inline auto get() noexcept
    { return _read_msr(addr); }

    namespace lock
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "lock";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace sgx_svn_sinit
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "sgx_svn_sinit";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        lock::dump(level);
        sgx_svn_sinit::dump(level);
    }
}

namespace ia32_rtit_output_base
{
    constexpr const auto addr = 0x00000560U;
    constexpr const auto name = "ia32_rtit_output_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace base_phys_address
    {
        constexpr const auto mask = 0x7FFFFFFFFFFFFF80ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "base_phys_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        base_phys_address::dump(level);
    }
}

namespace ia32_rtit_output_mask_ptrs
{
    constexpr const auto addr = 0x00000561U;
    constexpr const auto name = "ia32_rtit_output_mask_ptrs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace mask_table_offset
    {
        constexpr const auto mask = 0x00000000FFFFFF80ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "mask_table_offset";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace output_offset
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "output_offset";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        mask_table_offset::dump(level);
        output_offset::dump(level);
    }
}

namespace ia32_rtit_ctl
{
    constexpr const auto addr = 0x00000570U;
    constexpr const auto name = "ia32_rtit_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace traceen
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "traceen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cycen
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "cycen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace os
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "os";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace user
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "user";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fabricen
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "fabricen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cr3_filter
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "cr3_filter";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace topa
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "topa";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mtcen
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "mtcen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace tscen
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "tscen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace disretc
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "disretc";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace branchen
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "branchen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace mtcfreq
    {
        constexpr const auto mask = 0x000000000003C000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "mtcfreq";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cycthresh
    {
        constexpr const auto mask = 0x0000000000780000ULL;
        constexpr const auto from = 19;
        constexpr const auto name = "cycthresh";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace psbfreq
    {
        constexpr const auto mask = 0x000000000F000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "psbfreq";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace addr0_cfg
    {
        constexpr const auto mask = 0x0000000F00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "addr0_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace addr1_cfg
    {
        constexpr const auto mask = 0x000000F000000000ULL;
        constexpr const auto from = 36;
        constexpr const auto name = "addr1_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace addr2_cfg
    {
        constexpr const auto mask = 0x00000F0000000000ULL;
        constexpr const auto from = 40;
        constexpr const auto name = "addr2_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace addr3_cfg
    {
        constexpr const auto mask = 0x0000F00000000000ULL;
        constexpr const auto from = 44;
        constexpr const auto name = "addr3_cfg";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        traceen::dump(level);
        cycen::dump(level);
        os::dump(level);
        user::dump(level);
        fabricen::dump(level);
        cr3_filter::dump(level);
        topa::dump(level);
        mtcen::dump(level);
        tscen::dump(level);
        disretc::dump(level);
        branchen::dump(level);
        mtcfreq::dump(level);
        cycthresh::dump(level);
        psbfreq::dump(level);
        addr0_cfg::dump(level);
        addr1_cfg::dump(level);
        addr2_cfg::dump(level);
        addr3_cfg::dump(level);
    }
}

namespace ia32_rtit_status
{
    constexpr const auto addr = 0x00000571U;
    constexpr const auto name = "ia32_rtit_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace filteren
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "filteren";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace contexen
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "contexen";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace triggeren
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "triggeren";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace error
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "error";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace stopped
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "stopped";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace packetbytecnt
    {
        constexpr const auto mask = 0x0001FFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "packetbytecnt";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        filteren::dump(level);
        contexen::dump(level);
        triggeren::dump(level);
        error::dump(level);
        stopped::dump(level);
        packetbytecnt::dump(level);
    }
}

namespace ia32_rtit_cr3_match
{
    constexpr const auto addr = 0x00000572U;
    constexpr const auto name = "ia32_rtit_cr3_match";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace cr3
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFFFE0ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "cr3";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        cr3::dump(level);
    }
}

namespace ia32_rtit_addr0_a
{
    constexpr const auto addr = 0x00000580U;
    constexpr const auto name = "ia32_rtit_addr0_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr0_b
{
    constexpr const auto addr = 0x00000581U;
    constexpr const auto name = "ia32_rtit_addr0_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr1_a
{
    constexpr const auto addr = 0x00000582U;
    constexpr const auto name = "ia32_rtit_addr1_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr1_b
{
    constexpr const auto addr = 0x00000583U;
    constexpr const auto name = "ia32_rtit_addr1_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr2_a
{
    constexpr const auto addr = 0x00000584U;
    constexpr const auto name = "ia32_rtit_addr2_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr2_b
{
    constexpr const auto addr = 0x00000585U;
    constexpr const auto name = "ia32_rtit_addr2_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr3_a
{
    constexpr const auto addr = 0x00000586U;
    constexpr const auto name = "ia32_rtit_addr3_a";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_rtit_addr3_b
{
    constexpr const auto addr = 0x00000587U;
    constexpr const auto name = "ia32_rtit_addr3_b";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace virtual_address
    {
        constexpr const auto mask = 0x0000FFFFFFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "virtual_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace signext_va
    {
        constexpr const auto mask = 0xFFFF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "signext_va";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        virtual_address::dump(level);
        signext_va::dump(level);
    }
}

namespace ia32_ds_area
{
    constexpr const auto addr = 0x00000600U;
    constexpr const auto name = "ia32_ds_area";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_tsc_deadline
{
    constexpr const auto addr = 0x000006E0U;
    constexpr const auto name = "ia32_tsc_deadline";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_pm_enable
{
    constexpr const auto addr = 0x00000770U;
    constexpr const auto name = "ia32_pm_enable";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hwp
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        hwp::dump(level);
    }
}

namespace ia32_hwp_capabilities
{
    constexpr const auto addr = 0x00000771U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace guaranteed_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "guaranteed_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace most_efficient_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "most_efficient_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace lowest_perf
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "lowest_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        highest_perf::dump(level);
        guaranteed_perf::dump(level);
        most_efficient_perf::dump(level);
        lowest_perf::dump(level);
    }
}

namespace ia32_hwp_request_pkg
{
    constexpr const auto addr = 0x00000772U;
    constexpr const auto name = "ia32_hwp_request_pkg";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace min_perf
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "min_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace max_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "max_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace desired_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "desired_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace energy_perf_pref
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace activity_window
    {
        constexpr const auto mask = 0x000003FF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "activity_window";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        min_perf::dump(level);
        max_perf::dump(level);
        desired_perf::dump(level);
        energy_perf_pref::dump(level);
        activity_window::dump(level);
    }
}

namespace ia32_hwp_interrupt
{
    constexpr const auto addr = 0x00000773U;
    constexpr const auto name = "ia32_hwp_interrupt";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace perf_change
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "perf_change";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace excursion_min
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "excursion_min";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        perf_change::dump(level);
        excursion_min::dump(level);
    }
}

namespace ia32_hwp_request
{
    constexpr const auto addr = 0x00000774U;
    constexpr const auto name = "ia32_hwp_request";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace min_perf
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "min_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace max_perf
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "max_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace desired_perf
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "desired_perf";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace energy_perf_pref
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace activity_window
    {
        constexpr const auto mask = 0x000003FF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "energy_perf_pref";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace package_control
    {
        constexpr const auto mask = 0x0000040000000000ULL;
        constexpr const auto from = 42;
        constexpr const auto name = "package_control";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        min_perf::dump(level);
        max_perf::dump(level);
        desired_perf::dump(level);
        energy_perf_pref::dump(level);
        activity_window::dump(level);
        package_control::dump(level);
    }
}

namespace ia32_hwp_status
{
    constexpr const auto addr = 0x00000777U;
    constexpr const auto name = "ia32_hwp_status";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace perf_change
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "perf_change";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace excursion_to_min
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "excursion_to_min";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        perf_change::dump(level);
        excursion_to_min::dump(level);
    }
}

namespace ia32_x2apic_apicid
{
    constexpr const auto addr = 0x00000802U;
    constexpr const auto name = "ia32_x2apic_apicid";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_version
{
    constexpr const auto addr = 0x00000803U;
    constexpr const auto name = "ia32_x2apic_version";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tpr
{
    constexpr const auto addr = 0x00000808U;
    constexpr const auto name = "ia32_x2apic_tpr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_ppr
{
    constexpr const auto addr = 0x0000080AU;
    constexpr const auto name = "ia32_x2apic_ppr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_eoi
{
    constexpr const auto addr = 0x0000080BU;
    constexpr const auto name = "ia32_x2apic_eoi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ia32_x2apic_ldr
{
    constexpr const auto addr = 0x0000080DU;
    constexpr const auto name = "ia32_x2apic_ldr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_sivr
{
    constexpr const auto addr = 0x0000080FU;
    constexpr const auto name = "ia32_x2apic_sivr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr0
{
    constexpr const auto addr = 0x00000810U;
    constexpr const auto name = "ia32_x2apic_isr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr1
{
    constexpr const auto addr = 0x00000811U;
    constexpr const auto name = "ia32_x2apic_isr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr2
{
    constexpr const auto addr = 0x00000812U;
    constexpr const auto name = "ia32_x2apic_isr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr3
{
    constexpr const auto addr = 0x00000813U;
    constexpr const auto name = "ia32_x2apic_isr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr4
{
    constexpr const auto addr = 0x00000814U;
    constexpr const auto name = "ia32_x2apic_isr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr5
{
    constexpr const auto addr = 0x00000815U;
    constexpr const auto name = "ia32_x2apic_isr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr6
{
    constexpr const auto addr = 0x00000816U;
    constexpr const auto name = "ia32_x2apic_isr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_isr7
{
    constexpr const auto addr = 0x00000817U;
    constexpr const auto name = "ia32_x2apic_isr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr0
{
    constexpr const auto addr = 0x00000818U;
    constexpr const auto name = "ia32_x2apic_tmr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr1
{
    constexpr const auto addr = 0x00000819U;
    constexpr const auto name = "ia32_x2apic_tmr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr2
{
    constexpr const auto addr = 0x0000081AU;
    constexpr const auto name = "ia32_x2apic_tmr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr3
{
    constexpr const auto addr = 0x0000081BU;
    constexpr const auto name = "ia32_x2apic_tmr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr4
{
    constexpr const auto addr = 0x0000081CU;
    constexpr const auto name = "ia32_x2apic_tmr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr5
{
    constexpr const auto addr = 0x0000081DU;
    constexpr const auto name = "ia32_x2apic_tmr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr6
{
    constexpr const auto addr = 0x0000081EU;
    constexpr const auto name = "ia32_x2apic_tmr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_tmr7
{
    constexpr const auto addr = 0x0000081FU;
    constexpr const auto name = "ia32_x2apic_tmr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr0
{
    constexpr const auto addr = 0x00000820U;
    constexpr const auto name = "ia32_x2apic_irr0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr1
{
    constexpr const auto addr = 0x00000821U;
    constexpr const auto name = "ia32_x2apic_irr1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr2
{
    constexpr const auto addr = 0x00000822U;
    constexpr const auto name = "ia32_x2apic_irr2";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr3
{
    constexpr const auto addr = 0x00000823U;
    constexpr const auto name = "ia32_x2apic_irr3";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr4
{
    constexpr const auto addr = 0x00000824U;
    constexpr const auto name = "ia32_x2apic_irr4";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr5
{
    constexpr const auto addr = 0x00000825U;
    constexpr const auto name = "ia32_x2apic_irr5";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr6
{
    constexpr const auto addr = 0x00000826U;
    constexpr const auto name = "ia32_x2apic_irr6";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_irr7
{
    constexpr const auto addr = 0x00000827U;
    constexpr const auto name = "ia32_x2apic_irr7";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_esr
{
    constexpr const auto addr = 0x00000828U;
    constexpr const auto name = "ia32_x2apic_esr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_cmci
{
    constexpr const auto addr = 0x0000082FU;
    constexpr const auto name = "ia32_x2apic_lvt_cmci";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_icr
{
    constexpr const auto addr = 0x00000830U;
    constexpr const auto name = "ia32_x2apic_icr";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_timer
{
    constexpr const auto addr = 0x00000832U;
    constexpr const auto name = "ia32_x2apic_lvt_timer";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_thermal
{
    constexpr const auto addr = 0x00000833U;
    constexpr const auto name = "ia32_x2apic_lvt_thermal";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_pmi
{
    constexpr const auto addr = 0x00000834U;
    constexpr const auto name = "ia32_x2apic_lvt_pmi";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_lint0
{
    constexpr const auto addr = 0x00000835U;
    constexpr const auto name = "ia32_x2apic_lvt_lint0";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_lint1
{
    constexpr const auto addr = 0x00000836U;
    constexpr const auto name = "ia32_x2apic_lvt_lint1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_lvt_error
{
    constexpr const auto addr = 0x00000837U;
    constexpr const auto name = "ia32_x2apic_lvt_error";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_init_count
{
    constexpr const auto addr = 0x00000838U;
    constexpr const auto name = "ia32_x2apic_init_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_cur_count
{
    constexpr const auto addr = 0x00000839U;
    constexpr const auto name = "ia32_x2apic_cur_count";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_div_conf
{
    constexpr const auto addr = 0x0000083EU;
    constexpr const auto name = "ia32_x2apic_div_conf";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_x2apic_self_ipi
{
    constexpr const auto addr = 0x0000083FU;
    constexpr const auto name = "ia32_x2apic_self_ipi";

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }
}

namespace ia32_debug_interface
{
    constexpr const auto addr = 0x00000C80U;
    constexpr const auto name = "ia32_debug_interface";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lock
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "lock";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace debug_occurred
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31;
        constexpr const auto name = "debug_occurred";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        enable::dump(level);
        lock::dump(level);
        debug_occurred::dump(level);
   }
}

namespace ia32_l3_qos_cfg
{
    constexpr const auto addr = 0x00000C81U;
    constexpr const auto name = "ia32_l3_qos_cfg";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        enable::dump(level);
    }
}

namespace ia32_qm_evtsel
{
    constexpr const auto addr = 0x00000C8DU;
    constexpr const auto name = "ia32_qm_evtsel";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace event_id
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "event_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace resource_monitoring_id
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "resource_monitoring_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        event_id::dump(level);
        resource_monitoring_id::dump(level);
    }
}

namespace ia32_qm_ctr
{
    constexpr const auto addr = 0x00000C8EU;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace unavailable
    {
        constexpr const auto mask = 0x4000000000000000ULL;
        constexpr const auto from = 62;
        constexpr const auto name = "unavailable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace error
    {
        constexpr const auto mask = 0x8000000000000000ULL;
        constexpr const auto from = 63;
        constexpr const auto name = "error";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        resource_monitored_data::dump(level);
        unavailable::dump(level);
        error::dump(level);
    }
}

namespace ia32_pqr_assoc
{
    constexpr const auto addr = 0x00000C8FU;
    constexpr const auto name = "ia32_pqr_assoc";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace resource_monitoring_id
    {
        constexpr const auto mask = 0x00000000FFFFFFFFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "resource_monitoring_id";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    namespace cos
    {
        constexpr const auto mask = 0xFFFFFFFF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "cos";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        resource_monitoring_id::dump(level);
        cos::dump(level);
    }
}

namespace ia32_bndcfgs
{
    constexpr const auto addr = 0x00000D90U;
    constexpr const auto name = "ia32_bndcfgs";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace en
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "en";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace bndpreserve
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "bndpreserve";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace base_address
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "base_address";

        inline auto get() noexcept
        { return get_bits(_read_msr(addr), mask) >> from; }

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        en::dump(level);
        bndpreserve::dump(level);
        base_address::dump(level);
    }
}

namespace ia32_xss
{
    constexpr const auto addr = 0x00000DA0U;
    constexpr const auto name = "ia32_xss";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace trace_packet
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "trace_packet";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        trace_packet::dump(level);
    }
}

namespace ia32_pkg_hdc_ctl
{
    constexpr const auto addr = 0x00000DB0U;
    constexpr const auto name = "ia32_pkg_hdc_ctl";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hdc_pkg_enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "hdc_pkg_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        hdc_pkg_enable::dump(level);
    }
}

namespace ia32_pm_ctl1
{
    constexpr const auto addr = 0x00000DB1U;
    constexpr const auto name = "ia32_pm_ctl1";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace hdc_allow_block
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "hdc_allow_block";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        hdc_allow_block::dump(level);
    }
}

namespace ia32_thread_stall
{
    constexpr const auto addr = 0x00000DB2U;
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

        inline auto get(value_type msr) noexcept
        { return get_bits(msr, mask) >> from; }

        inline void set(value_type val) noexcept
        { _write_msr(addr, set_bits(_read_msr(addr), mask, val << from)); }

        inline auto set(value_type msr, value_type val) noexcept
        { return set_bits(msr, mask, val << from); }

        inline void dump(int level)
        { bfdebug_subnhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        stall_cycle_cnt::dump(level);
    }
}

namespace ia32_efer
{
    constexpr const auto addr = 0xC0000080U;
    constexpr const auto name = "ia32_efer";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "lma";

        inline auto is_enabled()
        { return is_bit_set(_read_msr(addr), from); }

        inline auto is_enabled(value_type msr)
        { return is_bit_set(msr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_msr(addr), from); }

        inline auto is_disabled(value_type msr)
        { return is_bit_cleared(msr, from); }

        inline void enable()
        { _write_msr(addr, set_bit(_read_msr(addr), from)); }

        inline auto enable(value_type msr)
        { return set_bit(msr, from); }

        inline void disable()
        { _write_msr(addr, clear_bit(_read_msr(addr), from)); }

        inline auto disable(value_type msr)
        { return clear_bit(msr, from); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        sce::dump(level);
        lme::dump(level);
        lma::dump(level);
        nxe::dump(level);
    }
}

namespace ia32_fs_base
{
    constexpr const auto addr = 0xC0000100U;
    constexpr const auto name = "ia32_fs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace ia32_gs_base
{
    constexpr const auto addr = 0xC0000101U;
    constexpr const auto name = "ia32_gs_base";

    inline auto get() noexcept
    { return _read_msr(addr); }

    inline void set(value_type val) noexcept
    { _write_msr(addr, val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

}
}

// *INDENT-ON*

#endif

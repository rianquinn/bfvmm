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

#ifndef CPUID_INTEL_X64_H
#define CPUID_INTEL_X64_H

#include <intrinsics/x86/common/cpuid_x64.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace cpuid
{

using field_type = x64::cpuid::field_type;
using value_type = x64::cpuid::value_type;

namespace feature_information
{
    constexpr const auto addr = 0x00000001ULL;

    namespace ecx
    {
        constexpr const auto name = "feature_information_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace sse3
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "sse3";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace pclmulqdq
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "pclmulqdq";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace dtes64
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "dtes64";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace monitor
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "monitor";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace ds_cpl
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "ds_cpl";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace vmx
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "vmx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace smx
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "smx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace eist
        {
            constexpr const auto mask = 0x00000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "eist";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace tm2
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "tm2";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace ssse3
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "ssse3";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace cnxt_id
        {
            constexpr const auto mask = 0x00000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "cnxt_id";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace sdbg
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "sdbg";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace fma
        {
            constexpr const auto mask = 0x00001000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "fma";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace cmpxchg16b
        {
            constexpr const auto mask = 0x00002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "cmpxchg16b";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace xtpr_update_control
        {
            constexpr const auto mask = 0x00004000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "xtpr_update_control";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace pdcm
        {
            constexpr const auto mask = 0x00008000ULL;
            constexpr const auto from = 15;
            constexpr const auto name = "pdcm";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace pcid
        {
            constexpr const auto mask = 0x00020000ULL;
            constexpr const auto from = 17;
            constexpr const auto name = "pcid";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace dca
        {
            constexpr const auto mask = 0x00040000ULL;
            constexpr const auto from = 18;
            constexpr const auto name = "dca";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace sse41
        {
            constexpr const auto mask = 0x00080000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "sse41";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace sse42
        {
            constexpr const auto mask = 0x00100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "sse42";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace x2apic
        {
            constexpr const auto mask = 0x00200000ULL;
            constexpr const auto from = 21;
            constexpr const auto name = "x2apic";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace movbe
        {
            constexpr const auto mask = 0x00400000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "movbe";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace popcnt
        {
            constexpr const auto mask = 0x00800000ULL;
            constexpr const auto from = 23;
            constexpr const auto name = "popcnt";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace tsc_deadline
        {
            constexpr const auto mask = 0x01000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "tsc_deadline";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace aesni
        {
            constexpr const auto mask = 0x02000000ULL;
            constexpr const auto from = 25;
            constexpr const auto name = "aesni";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace xsave
        {
            constexpr const auto mask = 0x04000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "xsave";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace osxsave
        {
            constexpr const auto mask = 0x08000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "osxsave";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace avx
        {
            constexpr const auto mask = 0x10000000ULL;
            constexpr const auto from = 28;
            constexpr const auto name = "avx";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace f16c
        {
            constexpr const auto mask = 0x20000000ULL;
            constexpr const auto from = 29;
            constexpr const auto name = "f16c";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace rdrand
        {
            constexpr const auto mask = 0x40000000ULL;
            constexpr const auto from = 30;
            constexpr const auto name = "rdrand";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            sse3::dump(level);
            pclmulqdq::dump(level);
            dtes64::dump(level);
            monitor::dump(level);
            ds_cpl::dump(level);
            vmx::dump(level);
            smx::dump(level);
            eist::dump(level);
            tm2::dump(level);
            ssse3::dump(level);
            cnxt_id::dump(level);
            sdbg::dump(level);
            fma::dump(level);
            cmpxchg16b::dump(level);
            xtpr_update_control::dump(level);
            pdcm::dump(level);
            pcid::dump(level);
            dca::dump(level);
            sse41::dump(level);
            sse42::dump(level);
            x2apic::dump(level);
            movbe::dump(level);
            popcnt::dump(level);
            tsc_deadline::dump(level);
            aesni::dump(level);
            xsave::dump(level);
            osxsave::dump(level);
            avx::dump(level);
            f16c::dump(level);
            rdrand::dump(level);
        }
    }

    inline void dump(int level)
    {
        ecx::dump(level);
    }
}

namespace extended_feature_flags
{
    constexpr const auto addr = 0x00000007ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0x0UL;

        namespace eax
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_input
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_input";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_input::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace fsgsbase
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "fsgsbase";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace ia32_tsc_adjust
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "ia32_tsc_adjust";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace sgx
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "sgx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace bmi1
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "bmi1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace hle
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4;
                constexpr const auto name = "hle";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace avx2
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5;
                constexpr const auto name = "avx2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace fdp_excptn_only
            {
                constexpr const auto mask = 0x00000040ULL;
                constexpr const auto from = 6;
                constexpr const auto name = "fdb_excptn_only";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace smep
            {
                constexpr const auto mask = 0x00000080ULL;
                constexpr const auto from = 7;
                constexpr const auto name = "smep";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace bmi2
            {
                constexpr const auto mask = 0x00000100ULL;
                constexpr const auto from = 8;
                constexpr const auto name = "bmi2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace movsb
            {
                constexpr const auto mask = 0x00000200ULL;
                constexpr const auto from = 9;
                constexpr const auto name = "movsb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace invpcid
            {
                constexpr const auto mask = 0x00000400ULL;
                constexpr const auto from = 10;
                constexpr const auto name = "invpcid";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace rtm
            {
                constexpr const auto mask = 0x00000800ULL;
                constexpr const auto from = 11;
                constexpr const auto name = "rtm";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace rtm_m
            {
                constexpr const auto mask = 0x00001000ULL;
                constexpr const auto from = 12;
                constexpr const auto name = "rtm_m";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace fpucs_fpuds
            {
                constexpr const auto mask = 0x00002000ULL;
                constexpr const auto from = 13;
                constexpr const auto name = "fpucs_fpuds";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace mpx
            {
                constexpr const auto mask = 0x00004000ULL;
                constexpr const auto from = 14;
                constexpr const auto name = "mpx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace rdt_a
            {
                constexpr const auto mask = 0x00008000ULL;
                constexpr const auto from = 15;
                constexpr const auto name = "rdt_a";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace rdseed
            {
                constexpr const auto mask = 0x00040000ULL;
                constexpr const auto from = 18;
                constexpr const auto name = "rdseed";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace adx
            {
                constexpr const auto mask = 0x00080000ULL;
                constexpr const auto from = 19;
                constexpr const auto name = "adx";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace smap
            {
                constexpr const auto mask = 0x00100000ULL;
                constexpr const auto from = 20;
                constexpr const auto name = "smap";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace clflushopt
            {
                constexpr const auto mask = 0x00800000ULL;
                constexpr const auto from = 23;
                constexpr const auto name = "clflushopt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace clwb
            {
                constexpr const auto mask = 0x01000000ULL;
                constexpr const auto from = 24;
                constexpr const auto name = "clwb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace trace
            {
                constexpr const auto mask = 0x02000000ULL;
                constexpr const auto from = 25;
                constexpr const auto name = "trace";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace sha
            {
                constexpr const auto mask = 0x20000000ULL;
                constexpr const auto from = 29;
                constexpr const auto name = "sha";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                fsgsbase::dump(level);
                ia32_tsc_adjust::dump(level);
                sgx::dump(level);
                bmi1::dump(level);
                hle::dump(level);
                avx2::dump(level);
                fdp_excptn_only::dump(level);
                smep::dump(level);
                bmi2::dump(level);
                movsb::dump(level);
                invpcid::dump(level);
                rtm::dump(level);
                rtm_m::dump(level);
                fpucs_fpuds::dump(level);
                mpx::dump(level);
                rdt_a::dump(level);
                rdseed::dump(level);
                adx::dump(level);
                smap::dump(level);
                clflushopt::dump(level);
                clwb::dump(level);
                trace::dump(level);
                sha::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_feature_flags_subleaf0_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace prefetchwt1
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "prefetchwt1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace umip
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "umip";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace pku
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "pku";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace ospke
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4;
                constexpr const auto name = "ospke";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace mawau
            {
                constexpr const auto mask = 0x003E0000ULL;
                constexpr const auto from = 17;
                constexpr const auto name = "mawau";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace rdpid
            {
                constexpr const auto mask = 0x00400000ULL;
                constexpr const auto from = 22;
                constexpr const auto name = "rdpid";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace sgx_lc
            {
                constexpr const auto mask = 0x40000000ULL;
                constexpr const auto from = 30;
                constexpr const auto name = "sgx_lc";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                prefetchwt1::dump(level);
                umip::dump(level);
                pku::dump(level);
                ospke::dump(level);
                mawau::dump(level);
                rdpid::dump(level);
                sgx_lc::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
        }
    }

    inline void dump(int level)
    {
        subleaf0::dump(level);
    }
}

namespace arch_perf_monitoring
{
    constexpr const auto addr = 0x0000000AULL;

    namespace eax
    {
        constexpr const auto name = "arch_perf_monitoring_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace version_id
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0UL;
            constexpr const auto name = "version_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace gppmc_count
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8UL;
            constexpr const auto name = "gppmc_count";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace gppmc_bit_width
        {
            constexpr const auto mask = 0x00FF0000ULL;
            constexpr const auto from = 16UL;
            constexpr const auto name = "gppmc_bit_width";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace ebx_enumeration_length
        {
            constexpr const auto mask = 0xFF000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "ebx_enumeration_length";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            version_id::dump(level);
            gppmc_count::dump(level);
            gppmc_bit_width::dump(level);
            ebx_enumeration_length::dump(level);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "arch_perf_monitoring_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace core_cycle_event
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0ULL;
            constexpr const auto name = "core_cycle_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace instr_retired_event
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1ULL;
            constexpr const auto name = "instr_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace reference_cycles_event
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2ULL;
            constexpr const auto name = "reference_cycles_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace llc_reference_event
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3ULL;
            constexpr const auto name = "llc_reference_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace llc_misses_event
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4ULL;
            constexpr const auto name = "llc_misses_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace branch_instr_retired_event
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5ULL;
            constexpr const auto name = "branch_instr_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace branch_mispredict_retired_event
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6ULL;
            constexpr const auto name = "branch_mispredict_retired_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ebx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ebx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            core_cycle_event::dump(level);
            instr_retired_event::dump(level);
            reference_cycles_event::dump(level);
            llc_reference_event::dump(level);
            llc_misses_event::dump(level);
            branch_instr_retired_event::dump(level);
            branch_mispredict_retired_event::dump(level);
        }
    }

    namespace edx
    {
        constexpr const auto name = "arch_perf_monitoring_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace ffpmc_count
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "ffpmc_count";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace ffpmc_bit_width
        {
            constexpr const auto mask = 0x00001FE0ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "ffpmc_bit_width";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            ffpmc_count::dump(level);
            ffpmc_bit_width::dump(level);
        }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        edx::dump(level);
    }
}

namespace cache_tlb_info
{
    constexpr const auto addr = 0x00000002ULL;

    namespace eax
    {
        constexpr const auto name = "cache_tlb_info_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ebx
    {
        constexpr const auto name = "cache_tlb_info_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ecx
    {
        constexpr const auto name = "cache_tlb_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace edx
    {
        constexpr const auto name = "cache_tlb_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        ecx::dump(level);
        edx::dump(level);
    }
}

namespace serial_num
{
    constexpr const auto addr = 0x00000003ULL;

    namespace ecx
    {
        constexpr const auto name = "cache_tlb_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace edx
    {
        constexpr const auto name = "cache_tlb_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }
}

namespace cache_parameters
{
    constexpr const auto addr = 0x00000004ULL;

    namespace eax
    {
        constexpr const auto name = "cache_parameters_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace cache_type
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "cache_type";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace cache_level
        {
            constexpr const auto mask = 0x000000E0ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "cache_level";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace self_init_level
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "self_init_level";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace fully_associative
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "fully_associative";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace max_ids_logical
        {
            constexpr const auto mask = 0x03FFC000ULL;
            constexpr const auto from = 14;
            constexpr const auto name = "max_ids_logical";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace max_ids_physical
        {
            constexpr const auto mask = 0xFC000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "max_ids_physical";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            cache_type::dump(level);
            cache_level::dump(level);
            self_init_level::dump(level);
            fully_associative::dump(level);
            max_ids_logical::dump(level);
            max_ids_physical::dump(level);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "cache_parameters_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace l
        {
            constexpr const auto mask = 0x00000FFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "l";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace p
        {
            constexpr const auto mask = 0x003FF000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "p";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace w
        {
            constexpr const auto mask = 0xFFC00000ULL;
            constexpr const auto from = 22;
            constexpr const auto name = "w";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            l::dump(level);
            p::dump(level);
            w::dump(level);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "cache_parameters_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace num_sets
        {
            constexpr const auto mask = 0xFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "num_sets";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            num_sets::dump(level);
        }
    }

    namespace edx
    {
        constexpr const auto name = "cache_parameters_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace wbinvd_invd
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "wbinvd_invd";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace cache_inclusiveness
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "cache_inclusiveness";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace complex_cache_indexing
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "complex_cache_indexing";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            wbinvd_invd::dump(level);
            cache_inclusiveness::dump(level);
            complex_cache_indexing::dump(level);
        }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        ecx::dump(level);
        edx::dump(level);
    }
}

namespace monitor_mwait
{
    constexpr const auto addr = 0x00000005ULL;

    namespace eax
    {
        constexpr const auto name = "monitor_mwait_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace min_line_size
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "min_line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            min_line_size::dump(level);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "monitor_mwait_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace max_line_size
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "max_line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            max_line_size::dump(level);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "monitor_mwait_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace enum_mwait_extensions
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "enum_mwait_extensions";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace interrupt_break_event
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "interrupt_break_event";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            enum_mwait_extensions::dump(level);
            interrupt_break_event::dump(level);
        }
    }

    namespace edx
    {
        constexpr const auto name = "monitor_mwait_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace num_c0
        {
            constexpr const auto mask = 0x0000000FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "num_c0";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c1
        {
            constexpr const auto mask = 0x000000F0ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "num_c1";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c2
        {
            constexpr const auto mask = 0x00000F00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "num_c2";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c3
        {
            constexpr const auto mask = 0x0000F000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "num_c3";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c4
        {
            constexpr const auto mask = 0x000F0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "num_c4";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c5
        {
            constexpr const auto mask = 0x00F00000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "num_c5";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c6
        {
            constexpr const auto mask = 0x0F000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "num_c6";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace num_c7
        {
            constexpr const auto mask = 0xF0000000ULL;
            constexpr const auto from = 28;
            constexpr const auto name = "num_c7";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            num_c0::dump(level);
            num_c1::dump(level);
            num_c2::dump(level);
            num_c3::dump(level);
            num_c4::dump(level);
            num_c5::dump(level);
            num_c6::dump(level);
            num_c7::dump(level);
        }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        ecx::dump(level);
        edx::dump(level);
    }
}

namespace therm_power_management
{
    constexpr const auto addr = 0x00000006ULL;

    namespace eax
    {
        constexpr const auto name = "therm_power_management_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace temp_sensor
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "temp_sensor";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace intel_turbo
        {
            constexpr const auto mask = 0x00000002ULL;
            constexpr const auto from = 1;
            constexpr const auto name = "intel_turbo";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace arat
        {
            constexpr const auto mask = 0x00000004ULL;
            constexpr const auto from = 2;
            constexpr const auto name = "arat";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace pln
        {
            constexpr const auto mask = 0x00000010ULL;
            constexpr const auto from = 4;
            constexpr const auto name = "pln";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace ecmd
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "ecmd";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace ptm
        {
            constexpr const auto mask = 0x00000040ULL;
            constexpr const auto from = 6;
            constexpr const auto name = "ptm";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hwp
        {
            constexpr const auto mask = 0x00000080ULL;
            constexpr const auto from = 7;
            constexpr const auto name = "hwp";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hwp_notification
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "hwp_notification";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hwp_activity_window
        {
            constexpr const auto mask = 0x00000200ULL;
            constexpr const auto from = 9;
            constexpr const auto name = "hwp_activity_window";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hwp_energy_perf
        {
            constexpr const auto mask = 0x00000400ULL;
            constexpr const auto from = 10;
            constexpr const auto name = "hwp_energy_perf";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hwp_package_request
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "hwp_package_request";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace hdc
        {
            constexpr const auto mask = 0x00002000ULL;
            constexpr const auto from = 13;
            constexpr const auto name = "hdc";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_eax(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_eax(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            temp_sensor::dump(level);
            intel_turbo::dump(level);
            arat::dump(level);
            pln::dump(level);
            ecmd::dump(level);
            ptm::dump(level);
            hwp::dump(level);
            hwp_notification::dump(level);
            hwp_activity_window::dump(level);
            hwp_energy_perf::dump(level);
            hwp_package_request::dump(level);
            hdc::dump(level);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "therm_power_management_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace num_interrupts
        {
            constexpr const auto mask = 0x0000000FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "num_interrupts";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            num_interrupts::dump(level);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "therm_power_management_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace hardware_feedback
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "hardware_feedback";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace energy_perf_bias
        {
            constexpr const auto mask = 0x00000008ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "energy_perf_bias";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            hardware_feedback::dump(level);
            energy_perf_bias::dump(level);
        }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        ecx::dump(level);
    }
}

namespace access_cache
{
    constexpr const auto addr = 0x00000009ULL;

    namespace eax
    {
        constexpr const auto name = "access_cache_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    inline void dump(int level)
    {
        eax::dump(level);
    }
}

namespace topology_enumeration
{
    constexpr const auto addr = 0x0000000BULL;

    namespace eax
    {
        constexpr const auto name = "topology_enumeration_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        namespace x2apic_shift
        {
            constexpr const auto mask = 0x0000001FULL;
            constexpr const auto from = 0;
            constexpr const auto name = "x2apic_shift";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            x2apic_shift::dump(level);
        }
    }

    namespace ebx
    {
        constexpr const auto name = "topology_enumeration_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        namespace num_processors
        {
            constexpr const auto mask = 0x0000FFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "num_processors";

            inline auto get() noexcept
            { return get_bits(_cpuid_ebx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            num_processors::dump(level);
        }
    }

    namespace ecx
    {
        constexpr const auto name = "topology_enumeration_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace level_number
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "level_number";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace level_type
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "level_type";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            level_number::dump(level);
            level_type::dump(level);
        }
    }

    namespace edx
    {
        constexpr const auto name = "topology_enumeration_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace x2apic_id
        {
            constexpr const auto mask = 0xFFFFFFFFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "x2apic_id";

            inline auto get() noexcept
            { return get_bits(_cpuid_edx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            x2apic_id::dump(level);
        }
    }

    inline void dump(int level)
    {
        eax::dump(level);
        ebx::dump(level);
        ecx::dump(level);
        edx::dump(level);
    }
}

namespace extended_state_enum
{
    constexpr const auto addr = 0x0000000DULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "extended_state_enum_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace edx
        {
            constexpr const auto name = "extended_state_enum_mainleaf_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "extended_state_enum_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace xsaveopt
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "xsaveopt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace xsavec
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "xsavec";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace xgetbv
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "xgetbv";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace xsaves_xrstors
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "xsaves_xrstors";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                xsaveopt::dump(level);
                xsavec::dump(level);
                xgetbv::dump(level);
                xsaves_xrstors::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace xsave_size
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "xsave_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                xsave_size::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace supported_bits
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "supported_bits";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                supported_bits::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "extended_state_enum_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace supported_bits
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "supported_bits";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                supported_bits::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    inline void dump(int level)
    {
        mainleaf::dump(level);
        subleaf1::dump(level);
    }
}

namespace intel_rdt
{
    constexpr const auto addr = 0x0000000FULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace ebx
        {
            constexpr const auto name = "intel_rdt_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace rmid_max_range
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "rmid_max_range";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                rmid_max_range::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_rdt_subleaf0_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace l3_rdt
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "l3_rdt";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                l3_rdt::dump(level);
            }
        }

        inline void dump(int level)
        {
            ebx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace ebx
        {
            constexpr const auto name = "intel_rdt_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace conversion_factor
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "conversion_factor";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                conversion_factor::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_rdt_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace rmid_max_range
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "rmid_max_range";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                rmid_max_range::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_rdt_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace l3_occupancy
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "l3_occupancy";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace l3_total_bandwith
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "l3_total_bandwith";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace l3_local_bandwith
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "l3_local_bandwith";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subedx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subedx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                l3_occupancy::dump(level);
                l3_total_bandwith::dump(level);
                l3_local_bandwith::dump(level);
            }
        }

        inline void dump(int level)
        {
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    inline void dump(int level)
    {
        subleaf0::dump(level);
        subleaf1::dump(level);
    }
}

namespace allocation_enumeration
{
    constexpr const auto addr = 0x00000010ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace l3_cache
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "l3_cache";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace l2_cache
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "l2_cache";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace mem_bandwidth
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "mem_bandwidth";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                l3_cache::dump(level);
                l2_cache::dump(level);
                mem_bandwidth::dump(level);
            }
        }

        inline void dump(int level)
        {
            ebx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace mask_length
            {
                constexpr const auto mask = 0x0000001FULL;
                constexpr const auto from = 0;
                constexpr const auto name = "mask_length";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                mask_length::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace map
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "map";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                map::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace data_prio
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "data_prio";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                data_prio::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_cos::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf2
    {
        constexpr const auto leaf = 2UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace mask_length
            {
                constexpr const auto mask = 0x0000001FULL;
                constexpr const auto from = 0;
                constexpr const auto name = "mask_length";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                mask_length::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace map
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "map";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                map::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf2_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_cos::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf3
    {
        constexpr const auto leaf = 3UL;

        namespace eax
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_throttle
            {
                constexpr const auto mask = 0x00000FFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_throttle";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_throttle::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace linear
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "linear";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                linear::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "allocation_enumeration_subleaf3_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace max_cos
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_cos";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_cos::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    inline void dump(int level)
    {
        subleaf0::dump(level);
        subleaf1::dump(level);
        subleaf2::dump(level);
        subleaf3::dump(level);
    }
}

namespace intel_sgx
{
    constexpr const auto addr = 0x00000012ULL;

    namespace subleaf0
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf0_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace sgx1
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "sgx1";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace sgx2
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "sgx2";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subeax(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subeax(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                sgx1::dump(level);
                sgx2::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf0_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace miscselect
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "miscselect";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                miscselect::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf0_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace mes_not64
            {
                constexpr const auto mask = 0x000000FFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "mes_not64";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace mes_64
            {
                constexpr const auto mask = 0x0000FF00ULL;
                constexpr const auto from = 8;
                constexpr const auto name = "mes_64";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                mes_not64::dump(level);
                mes_64::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_sgx_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf2
    {
        constexpr const auto leaf = 2UL;

        namespace eax
        {
            constexpr const auto name = "intel_sgx_subleaf2_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace subleaf_type
            {
                constexpr const auto mask = 0x0000000FULL;
                constexpr const auto from = 0;
                constexpr const auto name = "subleaf_type";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace address
            {
                constexpr const auto mask = 0xFFFFF000ULL;
                constexpr const auto from = 12;
                constexpr const auto name = "address";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                subleaf_type::dump(level);
                address::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "intel_sgx_subleaf2_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace address
            {
                constexpr const auto mask = 0x000FFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "address";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                address::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "intel_sgx_subleaf2_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace epc_property
            {
                constexpr const auto mask = 0x0000000FULL;
                constexpr const auto from = 0;
                constexpr const auto name = "epc_property";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace epc_size
            {
                constexpr const auto mask = 0xFFFFF000ULL;
                constexpr const auto from = 12;
                constexpr const auto name = "epc_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                epc_property::dump(level);
                epc_size::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "intel_sgx_subleaf2_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace epc_size
            {
                constexpr const auto mask = 0x000FFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "epc_size";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                epc_size::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    inline void dump(int level)
    {
        subleaf0::dump(level);
        subleaf1::dump(level);
        subleaf2::dump(level);
    }
}

namespace trace_enumeration
{
    constexpr const auto addr = 0x00000014ULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "trace_enumeration_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_subleaf
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_subleaf";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_subleaf::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "trace_enumeration_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace ia32_rtit_ctlcr3filter
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "ia32_rtit_ctlcr3filter";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace configurable_psb
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "configurable_psb";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace ip_filtering
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "ip_filtering";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace mtc_timing_packet
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "mtc_timing_packet";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace ptwrite
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4;
                constexpr const auto name = "ptwrite";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace power_event_trace
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5;
                constexpr const auto name = "power_event_trace";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                ia32_rtit_ctlcr3filter::dump(level);
                configurable_psb::dump(level);
                ip_filtering::dump(level);
                mtc_timing_packet::dump(level);
                ptwrite::dump(level);
                power_event_trace::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "trace_enumeration_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace trading_enabled
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "trading_enabled";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace topa_entry
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "topa_entry";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace single_range_output
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "single_range_output";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace trace_transport
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "trace_transport";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            namespace lip_values
            {
                constexpr const auto mask = 0x80000000ULL;
                constexpr const auto from = 31;
                constexpr const auto name = "lip_values";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subecx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subecx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                trading_enabled::dump(level);
                topa_entry::dump(level);
                single_range_output::dump(level);
                trace_transport::dump(level);
                lip_values::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "trace_enumeration_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace num_address_ranges
            {
                constexpr const auto mask = 0x00000007ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "num_address_ranges";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace bitmap_mtc
            {
                constexpr const auto mask = 0xFFFF0000ULL;
                constexpr const auto from = 16;
                constexpr const auto name = "bitmap_mtc";

                inline auto get() noexcept
                { return get_bits(_cpuid_subeax(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                num_address_ranges::dump(level);
                bitmap_mtc::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "trace_enumeration_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace bitmap_cycle_threshold
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "bitmap_cycle_threshold";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace bitmap_psb
            {
                constexpr const auto mask = 0xFFFF0000ULL;
                constexpr const auto from = 16;
                constexpr const auto name = "bitmap_psb";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                bitmap_cycle_threshold::dump(level);
                bitmap_psb::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
        }
    }

    inline void dump(int level)
    {
        mainleaf::dump(level);
        subleaf1::dump(level);
    }
}

namespace time_stamp_count
{
    constexpr const auto addr = 0x00000015ULL;

    namespace eax
    {
        constexpr const auto name = "time_stamp_count_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ebx
    {
        constexpr const auto name = "time_stamp_count_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ecx
    {
        constexpr const auto name = "time_stamp_count_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }
}

namespace processor_freq
{
    constexpr const auto addr = 0x00000016ULL;

    namespace eax
    {
        constexpr const auto name = "processor_freq_eax";

        inline auto get() noexcept
        { return _cpuid_eax(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ebx
    {
        constexpr const auto name = "processor_freq_ebx";

        inline auto get() noexcept
        { return _cpuid_ebx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }

    namespace ecx
    {
        constexpr const auto name = "processor_freq_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        inline void dump(int level)
        { bfdebug_nhex(level, name, get()); }
    }
}

namespace vendor_attribute
{
    constexpr const auto addr = 0x00000017ULL;

    namespace mainleaf
    {
        constexpr const auto leaf = 0UL;

        namespace eax
        {
            constexpr const auto name = "vendor_attribute_mainleaf_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            namespace max_socid
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_socid";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                max_socid::dump(level);
            }
        }

        namespace ebx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            namespace soc_vendor
            {
                constexpr const auto mask = 0x0000FFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "soc_vendor";

                inline auto get() noexcept
                { return get_bits(_cpuid_subebx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            namespace is_vendor_scheme
            {
                constexpr const auto mask = 0x00010000ULL;
                constexpr const auto from = 16;
                constexpr const auto name = "is_vendor_scheme";

                inline auto is_enabled()
                { return is_bit_set(_cpuid_subebx(addr, leaf), from); }

                inline auto is_enabled(value_type msr)
                { return is_bit_set(msr, from); }

                inline auto is_disabled()
                { return is_bit_cleared(_cpuid_subebx(addr, leaf), from); }

                inline auto is_disabled(value_type msr)
                { return is_bit_cleared(msr, from); }

                inline void dump(int level)
                { bfdebug_subbool(level, name, is_enabled()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                soc_vendor::dump(level);
                is_vendor_scheme::dump(level);
            }
        }

        namespace ecx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            namespace project_id
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "project_id";

                inline auto get() noexcept
                { return get_bits(_cpuid_subecx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                project_id::dump(level);
            }
        }

        namespace edx
        {
            constexpr const auto name = "vendor_attribute_mainleaf_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            namespace stepping_id
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "stepping_id";

                inline auto get() noexcept
                { return get_bits(_cpuid_subedx(addr, leaf), mask) >> from; }

                inline auto get(value_type msr) noexcept
                { return get_bits(msr, mask) >> from; }

                inline void dump(int level)
                { bfdebug_subnhex(level, name, get()); }
            }

            inline void dump(int level)
            {
                bfdebug_nhex(level, name, get());
                stepping_id::dump(level);
            }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    namespace subleaf1
    {
        constexpr const auto leaf = 1UL;

        namespace eax
        {
            constexpr const auto name = "vendor_attribute_subleaf1_eax";

            inline auto get() noexcept
            { return _cpuid_subeax(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ebx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_ebx";

            inline auto get() noexcept
            { return _cpuid_subebx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace ecx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_ecx";

            inline auto get() noexcept
            { return _cpuid_subecx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        namespace edx
        {
            constexpr const auto name = "vendor_attribute_subleaf1_edx";

            inline auto get() noexcept
            { return _cpuid_subedx(addr, leaf); }

            inline void dump(int level)
            { bfdebug_nhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            eax::dump(level);
            ebx::dump(level);
            ecx::dump(level);
            edx::dump(level);
        }
    }

    inline void dump(int level)
    {
        mainleaf::dump(level);
        subleaf1::dump(level);
    }
}

namespace ext_feature_info
{
    constexpr const auto addr = 0x80000001ULL;

    namespace ecx
    {
        constexpr const auto name = "ext_feature_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace lahf_sahf
        {
            constexpr const auto mask = 0x00000001ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "lahf_sahf";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace lzcnt
        {
            constexpr const auto mask = 0x00000020ULL;
            constexpr const auto from = 5;
            constexpr const auto name = "lzcnt";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace prefetchw
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "prefetchw";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_ecx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_ecx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            lahf_sahf::dump(level);
            lzcnt::dump(level);
            prefetchw::dump(level);
        }
    }

    namespace edx
    {
        constexpr const auto name = "ext_feature_info_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace syscall_sysret
        {
            constexpr const auto mask = 0x00000800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "syscall_sysret";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace execute_disable_bit
        {
            constexpr const auto mask = 0x00100000ULL;
            constexpr const auto from = 20;
            constexpr const auto name = "execute_disable_bit";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace pages_avail
        {
            constexpr const auto mask = 0x04000000ULL;
            constexpr const auto from = 26;
            constexpr const auto name = "pages_avail";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace rdtscp
        {
            constexpr const auto mask = 0x08000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "rdtscp";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        namespace intel_64
        {
            constexpr const auto mask = 0x20000000ULL;
            constexpr const auto from = 29;
            constexpr const auto name = "intel_64";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            syscall_sysret::dump(level);
            execute_disable_bit::dump(level);
            pages_avail::dump(level);
            rdtscp::dump(level);
            intel_64::dump(level);
        }
    }

    inline void dump(int level)
    {
        ecx::dump(level);
        edx::dump(level);
    }
}

namespace l2_info
{
    constexpr const auto addr = 0x80000006ULL;

    namespace ecx
    {
        constexpr const auto name = "l2_info_ecx";

        inline auto get() noexcept
        { return _cpuid_ecx(addr); }

        namespace line_size
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "line_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace l2_associativity
        {
            constexpr const auto mask = 0x0000F000ULL;
            constexpr const auto from = 12;
            constexpr const auto name = "l2_associativity";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        namespace cache_size
        {
            constexpr const auto mask = 0xFFFF0000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "cache_size";

            inline auto get() noexcept
            { return get_bits(_cpuid_ecx(addr), mask) >> from; }

            inline auto get(value_type msr) noexcept
            { return get_bits(msr, mask) >> from; }

            inline void dump(int level)
            { bfdebug_subnhex(level, name, get()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            line_size::dump(level);
            l2_associativity::dump(level);
            cache_size::dump(level);
        }
    }

    inline void dump(int level)
    {
        ecx::dump(level);
    }
}

namespace invariant_tsc
{
    constexpr const auto addr = 0x80000007ULL;

    namespace edx
    {
        constexpr const auto name = "invariant_tsc_edx";

        inline auto get() noexcept
        { return _cpuid_edx(addr); }

        namespace available
        {
            constexpr const auto mask = 0x00000100ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "available";

            inline auto is_enabled()
            { return is_bit_set(_cpuid_edx(addr), from); }

            inline auto is_enabled(value_type msr)
            { return is_bit_set(msr, from); }

            inline auto is_disabled()
            { return is_bit_cleared(_cpuid_edx(addr), from); }

            inline auto is_disabled(value_type msr)
            { return is_bit_cleared(msr, from); }

            inline void dump(int level)
            { bfdebug_subbool(level, name, is_enabled()); }
        }

        inline void dump(int level)
        {
            bfdebug_nhex(level, name, get());
            available::dump(level);
        }
    }

    inline void dump(int level)
    {
        edx::dump(level);
    }
}

}
}

// *INDENT-ON*

#endif

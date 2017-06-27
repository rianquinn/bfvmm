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

#ifndef CPUID_X64_H
#define CPUID_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>
#include <iostream>

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

extern "C" EXPORT_INTRINSICS uint32_t _cpuid_eax(uint32_t val) noexcept;
extern "C" EXPORT_INTRINSICS uint32_t _cpuid_ebx(uint32_t val) noexcept;
extern "C" EXPORT_INTRINSICS uint32_t _cpuid_ecx(uint32_t val) noexcept;
extern "C" EXPORT_INTRINSICS uint32_t _cpuid_edx(uint32_t val) noexcept;
extern "C" EXPORT_INTRINSICS void _cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace cpuid
{
    using field_type = uint32_t;
    using value_type = uint32_t;

    template<
        typename T1,
        typename T2,
        typename T3,
        typename T4,
        typename = std::enable_if<std::is_integral<T1>::value>,
        typename = std::enable_if<std::is_integral<T2>::value>,
        typename = std::enable_if<std::is_integral<T3>::value>,
        typename = std::enable_if<std::is_integral<T4>::value>
        >
    auto get(T1 eax, T2 ebx, T3 ecx, T4 edx) noexcept
    {
        _cpuid(&eax, &ebx, &ecx, &edx);
        return std::make_tuple(eax, ebx, ecx, edx);
    }

    namespace eax
    {
        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        auto get(T eax) noexcept { return _cpuid_eax(gsl::narrow_cast<uint32_t>(eax)); }
    }

    namespace ebx
    {
        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        auto get(T ebx) noexcept { return _cpuid_ebx(gsl::narrow_cast<uint32_t>(ebx)); }
    }

    namespace ecx
    {
        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        auto get(T ecx) noexcept { return _cpuid_ecx(gsl::narrow_cast<uint32_t>(ecx)); }
    }

    namespace edx
    {
        template<typename T, typename = std::enable_if<std::is_integral<T>::value>>
        auto get(T edx) noexcept { return _cpuid_edx(gsl::narrow_cast<uint32_t>(edx)); }
    }

    namespace addr_size
    {
        constexpr const auto addr = 0x80000008ULL;
        constexpr const auto name = "addr_size";

        namespace phys
        {
            constexpr const auto mask = 0x000000FFULL;
            constexpr const auto from = 0;
            constexpr const auto name = "phys";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }
        }

        namespace linear
        {
            constexpr const auto mask = 0x0000FF00ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "linear";

            inline auto get() noexcept
            { return get_bits(_cpuid_eax(addr), mask) >> from; }
        }
    }

    namespace feature_information
    {
        constexpr const auto addr = 0x00000001ULL;
        constexpr const auto name = "feature_information";

        namespace ecx
        {
            namespace sse3
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0;
                constexpr const auto name = "sse3";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace pclmulqdq
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1;
                constexpr const auto name = "pclmulqdq";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace dtes64
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2;
                constexpr const auto name = "dtes64";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace monitor
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3;
                constexpr const auto name = "monitor";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace ds_cpl
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4;
                constexpr const auto name = "ds_cpl";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace vmx
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5;
                constexpr const auto name = "vmx";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace smx
            {
                constexpr const auto mask = 0x00000040ULL;
                constexpr const auto from = 6;
                constexpr const auto name = "smx";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace eist
            {
                constexpr const auto mask = 0x00000080ULL;
                constexpr const auto from = 7;
                constexpr const auto name = "eist";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace tm2
            {
                constexpr const auto mask = 0x00000100ULL;
                constexpr const auto from = 8;
                constexpr const auto name = "tm2";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace ssse3
            {
                constexpr const auto mask = 0x00000200ULL;
                constexpr const auto from = 9;
                constexpr const auto name = "ssse3";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace cnxt_id
            {
                constexpr const auto mask = 0x00000400ULL;
                constexpr const auto from = 10;
                constexpr const auto name = "cnxt_id";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace sdbg
            {
                constexpr const auto mask = 0x00000800ULL;
                constexpr const auto from = 11;
                constexpr const auto name = "sdbg";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace fma
            {
                constexpr const auto mask = 0x00001000ULL;
                constexpr const auto from = 12;
                constexpr const auto name = "fma";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace cmpxchg16b
            {
                constexpr const auto mask = 0x00002000ULL;
                constexpr const auto from = 13;
                constexpr const auto name = "cmpxchg16b";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace xtpr_update_control
            {
                constexpr const auto mask = 0x00004000ULL;
                constexpr const auto from = 14;
                constexpr const auto name = "xtpr_update_control";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace pdcm
            {
                constexpr const auto mask = 0x00008000ULL;
                constexpr const auto from = 15;
                constexpr const auto name = "pdcm";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace pcid
            {
                constexpr const auto mask = 0x00020000ULL;
                constexpr const auto from = 17;
                constexpr const auto name = "pcid";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace dca
            {
                constexpr const auto mask = 0x00040000ULL;
                constexpr const auto from = 18;
                constexpr const auto name = "dca";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace sse41
            {
                constexpr const auto mask = 0x00080000ULL;
                constexpr const auto from = 19;
                constexpr const auto name = "sse41";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace sse42
            {
                constexpr const auto mask = 0x00100000ULL;
                constexpr const auto from = 20;
                constexpr const auto name = "sse42";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace x2apic
            {
                constexpr const auto mask = 0x00200000ULL;
                constexpr const auto from = 21;
                constexpr const auto name = "x2apic";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace movbe
            {
                constexpr const auto mask = 0x00400000ULL;
                constexpr const auto from = 22;
                constexpr const auto name = "movbe";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace popcnt
            {
                constexpr const auto mask = 0x00800000ULL;
                constexpr const auto from = 23;
                constexpr const auto name = "popcnt";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace tsc_deadline
            {
                constexpr const auto mask = 0x01000000ULL;
                constexpr const auto from = 24;
                constexpr const auto name = "tsc_deadline";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace aesni
            {
                constexpr const auto mask = 0x02000000ULL;
                constexpr const auto from = 25;
                constexpr const auto name = "aesni";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace xsave
            {
                constexpr const auto mask = 0x04000000ULL;
                constexpr const auto from = 26;
                constexpr const auto name = "xsave";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace osxsave
            {
                constexpr const auto mask = 0x08000000ULL;
                constexpr const auto from = 27;
                constexpr const auto name = "osxsave";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace avx
            {
                constexpr const auto mask = 0x10000000ULL;
                constexpr const auto from = 28;
                constexpr const auto name = "avx";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace f16c
            {
                constexpr const auto mask = 0x20000000ULL;
                constexpr const auto from = 29;
                constexpr const auto name = "f16c";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            namespace rdrand
            {
                constexpr const auto mask = 0x40000000ULL;
                constexpr const auto from = 30;
                constexpr const auto name = "rdrand";

                inline auto get() noexcept
                { return get_bit(_cpuid_ecx(addr), from) != 0; }
            }

            inline void dump() noexcept
            {
                bfdebug << "cpuid::feature_information::ecx enabled flags:" << bfendl;

                if (sse3::get()) {
                    bfdebug << "    - sse3" << bfendl;
                }
                if (pclmulqdq::get()) {
                    bfdebug << "    - pclmulqdq" << bfendl;
                }
                if (dtes64::get()) {
                    bfdebug << "    - dtes64" << bfendl;
                }
                if (monitor::get()) {
                    bfdebug << "    - monitor" << bfendl;
                }
                if (ds_cpl::get()) {
                    bfdebug << "    - ds_cpl" << bfendl;
                }
                if (vmx::get()) {
                    bfdebug << "    - vmx" << bfendl;
                }
                if (smx::get()) {
                    bfdebug << "    - smx" << bfendl;
                }
                if (eist::get()) {
                    bfdebug << "    - eist" << bfendl;
                }
                if (tm2::get()) {
                    bfdebug << "    - tm2" << bfendl;
                }
                if (ssse3::get()) {
                    bfdebug << "    - ssse3" << bfendl;
                }
                if (cnxt_id::get()) {
                    bfdebug << "    - cnxt_id" << bfendl;
                }
                if (sdbg::get()) {
                    bfdebug << "    - sdbg" << bfendl;
                }
                if (fma::get()) {
                    bfdebug << "    - fma" << bfendl;
                }
                if (cmpxchg16b::get()) {
                    bfdebug << "    - cmpxchg16b" << bfendl;
                }
                if (xtpr_update_control::get()) {
                    bfdebug << "    - xtpr_update_control" << bfendl;
                }
                if (pdcm::get()) {
                    bfdebug << "    - pdcm" << bfendl;
                }
                if (pcid::get()) {
                    bfdebug << "    - pcid" << bfendl;
                }
                if (dca::get()) {
                    bfdebug << "    - dca" << bfendl;
                }
                if (sse41::get()) {
                    bfdebug << "    - sse41" << bfendl;
                }
                if (sse42::get()) {
                    bfdebug << "    - sse42" << bfendl;
                }
                if (x2apic::get()) {
                    bfdebug << "    - x2apic" << bfendl;
                }
                if (movbe::get()) {
                    bfdebug << "    - movbe" << bfendl;
                }
                if (popcnt::get()) {
                    bfdebug << "    - popcnt" << bfendl;
                }
                if (tsc_deadline::get()) {
                    bfdebug << "    - tsc_deadline" << bfendl;
                }
                if (aesni::get()) {
                    bfdebug << "    - aesni" << bfendl;
                }
                if (xsave::get()) {
                    bfdebug << "    - xsave" << bfendl;
                }
                if (osxsave::get()) {
                    bfdebug << "    - osxsave" << bfendl;
                }
                if (avx::get()) {
                    bfdebug << "    - avx" << bfendl;
                }
                if (f16c::get()) {
                    bfdebug << "    - f16c" << bfendl;
                }
                if (rdrand::get()) {
                    bfdebug << "    - rdrand" << bfendl;
                }
            }
        }
    }

    namespace extended_feature_flags
    {
        constexpr const auto addr = 0x00000007ULL;
        constexpr const auto name = "extended_feature_flags";

        namespace subleaf0
        {
            namespace eax
            {
                namespace max_input
                {
                    constexpr const auto mask = 0xFFFFFFFFULL;
                    constexpr const auto from = 0;
                    constexpr const auto name = "max_input";

                    inline auto get() noexcept
                    { return get_bits(_cpuid_eax(addr), mask) >> from; }
                }
            }

            namespace ebx
            {
                namespace fsgsbase
                {
                    constexpr const auto mask = 0x00000001ULL;
                    constexpr const auto from = 0;
                    constexpr const auto name = "fsgsbase";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace ia32_tsc_adjust
                {
                    constexpr const auto mask = 0x00000002ULL;
                    constexpr const auto from = 1;
                    constexpr const auto name = "ia32_tsc_adjust";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace sgx
                {
                    constexpr const auto mask = 0x00000004ULL;
                    constexpr const auto from = 2;
                    constexpr const auto name = "sgx";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace bmi1
                {
                    constexpr const auto mask = 0x00000008ULL;
                    constexpr const auto from = 3;
                    constexpr const auto name = "bmi1";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace hle
                {
                    constexpr const auto mask = 0x00000010ULL;
                    constexpr const auto from = 4;
                    constexpr const auto name = "hle";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace avx2
                {
                    constexpr const auto mask = 0x00000020ULL;
                    constexpr const auto from = 5;
                    constexpr const auto name = "avx2";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace fdp_excptn_only
                {
                    constexpr const auto mask = 0x00000040ULL;
                    constexpr const auto from = 6;
                    constexpr const auto name = "fdb_excptn_only";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace smep
                {
                    constexpr const auto mask = 0x00000080ULL;
                    constexpr const auto from = 7;
                    constexpr const auto name = "smep";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace bmi2
                {
                    constexpr const auto mask = 0x00000100ULL;
                    constexpr const auto from = 8;
                    constexpr const auto name = "bmi2";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace movsb
                {
                    constexpr const auto mask = 0x00000200ULL;
                    constexpr const auto from = 9;
                    constexpr const auto name = "movsb";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace invpcid
                {
                    constexpr const auto mask = 0x00000400ULL;
                    constexpr const auto from = 10;
                    constexpr const auto name = "invpcid";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace rtm
                {
                    constexpr const auto mask = 0x00000800ULL;
                    constexpr const auto from = 11;
                    constexpr const auto name = "rtm";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace rtm_m
                {
                    constexpr const auto mask = 0x00001000ULL;
                    constexpr const auto from = 12;
                    constexpr const auto name = "rtm_m";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace fpucs_fpuds
                {
                    constexpr const auto mask = 0x00002000ULL;
                    constexpr const auto from = 13;
                    constexpr const auto name = "fpucs_fpuds";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace mpx
                {
                    constexpr const auto mask = 0x00004000ULL;
                    constexpr const auto from = 14;
                    constexpr const auto name = "mpx";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace rdt_a
                {
                    constexpr const auto mask = 0x00008000ULL;
                    constexpr const auto from = 15;
                    constexpr const auto name = "rdt_a";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace rdseed
                {
                    constexpr const auto mask = 0x00040000ULL;
                    constexpr const auto from = 18;
                    constexpr const auto name = "rdseed";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace adx
                {
                    constexpr const auto mask = 0x00080000ULL;
                    constexpr const auto from = 19;
                    constexpr const auto name = "adx";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace smap
                {
                    constexpr const auto mask = 0x00100000ULL;
                    constexpr const auto from = 20;
                    constexpr const auto name = "smap";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace clflushopt
                {
                    constexpr const auto mask = 0x00800000ULL;
                    constexpr const auto from = 23;
                    constexpr const auto name = "clflushopt";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace clwb
                {
                    constexpr const auto mask = 0x01000000ULL;
                    constexpr const auto from = 24;
                    constexpr const auto name = "clwb";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace trace
                {
                    constexpr const auto mask = 0x02000000ULL;
                    constexpr const auto from = 25;
                    constexpr const auto name = "trace";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }

                namespace sha
                {
                    constexpr const auto mask = 0x20000000ULL;
                    constexpr const auto from = 29;
                    constexpr const auto name = "sha";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ebx(addr), from) != 0; }
                }
            }

            namespace ecx
            {
                namespace prefetchwt1
                {
                    constexpr const auto mask = 0x00000001ULL;
                    constexpr const auto from = 0;
                    constexpr const auto name = "prefetchwt1";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }

                namespace umip
                {
                    constexpr const auto mask = 0x00000004ULL;
                    constexpr const auto from = 2;
                    constexpr const auto name = "umip";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }

                namespace pku
                {
                    constexpr const auto mask = 0x00000008ULL;
                    constexpr const auto from = 3;
                    constexpr const auto name = "pku";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }

                namespace ospke
                {
                    constexpr const auto mask = 0x00000010ULL;
                    constexpr const auto from = 4;
                    constexpr const auto name = "ospke";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }

                namespace mawau
                {
                    constexpr const auto mask = 0x003E0000ULL;
                    constexpr const auto from = 17;
                    constexpr const auto name = "mawau";

                    inline auto get() noexcept
                    { return get_bits(_cpuid_ecx(addr), mask) >> from; }
                }

                namespace rdpid
                {
                    constexpr const auto mask = 0x00400000ULL;
                    constexpr const auto from = 22;
                    constexpr const auto name = "rdpid";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }

                namespace sgx_lc
                {
                    constexpr const auto mask = 0x40000000ULL;
                    constexpr const auto from = 30;
                    constexpr const auto name = "sgx_lc";

                    inline auto get() noexcept
                    { return get_bit(_cpuid_ecx(addr), from) != 0; }
                }
            }
        }
    }

    namespace arch_perf_monitoring
    {
        constexpr const auto addr = 0x0000000AULL;
        constexpr const auto name = "arch_perf_monitoring";

        namespace eax
        {
            namespace version_id
            {
                constexpr const auto mask = 0x000000FFULL;
                constexpr const auto from = 0UL;
                constexpr const auto name = "version_id";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }

            namespace gppmc_count
            {
                constexpr const auto mask = 0x0000FF00ULL;
                constexpr const auto from = 8UL;
                constexpr const auto name = "gppmc_count";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }

            namespace gppmc_bit_width
            {
                constexpr const auto mask = 0x00FF0000ULL;
                constexpr const auto from = 16UL;
                constexpr const auto name = "gppmc_bit_width";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }

            namespace ebx_enumeration_length
            {
                constexpr const auto mask = 0xFF000000ULL;
                constexpr const auto from = 24;
                constexpr const auto name = "ebx_enumeration_length";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }

        namespace ebx
        {
            namespace core_cycle_event
            {
                constexpr const auto mask = 0x00000001ULL;
                constexpr const auto from = 0ULL;
                constexpr const auto name = "core_cycle_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace instr_retired_event
            {
                constexpr const auto mask = 0x00000002ULL;
                constexpr const auto from = 1ULL;
                constexpr const auto name = "instr_retired_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace reference_cycles_event
            {
                constexpr const auto mask = 0x00000004ULL;
                constexpr const auto from = 2ULL;
                constexpr const auto name = "reference_cycles_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace llc_reference_event
            {
                constexpr const auto mask = 0x00000008ULL;
                constexpr const auto from = 3ULL;
                constexpr const auto name = "llc_reference_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace llc_misses_event
            {
                constexpr const auto mask = 0x00000010ULL;
                constexpr const auto from = 4ULL;
                constexpr const auto name = "llc_misses_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace branch_instr_retired_event
            {
                constexpr const auto mask = 0x00000020ULL;
                constexpr const auto from = 5ULL;
                constexpr const auto name = "branch_instr_retired_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }

            namespace branch_mispredict_retired_event
            {
                constexpr const auto mask = 0x00000040ULL;
                constexpr const auto from = 6ULL;
                constexpr const auto name = "branch_mispredict_retired_event";

                inline auto get() noexcept
                { return get_bit(_cpuid_ebx(addr), from) != 0; }
            }
        }

        namespace edx
        {
            namespace ffpmc_count
            {
                constexpr const auto mask = 0x0000001FULL;
                constexpr const auto from = 0;
                constexpr const auto name = "ffpmc_count";

                inline auto get() noexcept
                { return get_bits(_cpuid_edx(addr), mask) >> from; }
            }

            namespace ffpmc_bit_width
            {
                constexpr const auto mask = 0x00001FE0ULL;
                constexpr const auto from = 5;
                constexpr const auto name = "ffpmc_bit_width";

                inline auto get() noexcept
                { return get_bits(_cpuid_edx(addr), mask) >> from; }
            }
        }
    }

    namespace basic_cpuid_info
    {
        constexpr const auto addr = 0x00000000ULL;
        constexpr const auto name = "basic_cpuid_info";

        namespace eax
        {
            namespace max_input_value
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_input_value";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }
    }

    namespace extend_cpuid_info
    {
        constexpr const auto addr = 0x80000000ULL;
        constexpr const auto name = "extend_cpuid_info";

        namespace eax
        {
            namespace max_input_value
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "max_input_value";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }
    }

    namespace processor_string_1
    {
        constexpr const auto addr = 0x80000002ULL;
        constexpr const auto name = "processor_string_1";

        namespace eax
        {
            namespace part_1
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_1";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }

        namespace ebx
        {
            namespace part_2
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_2";

                inline auto get() noexcept
                { return get_bits(_cpuid_ebx(addr), mask) >> from; }
            }
        }

        namespace ecx
        {
            namespace part_3
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_3";

                inline auto get() noexcept
                { return get_bits(_cpuid_ecx(addr), mask) >> from; }
            }
        }

        namespace edx
        {
            namespace part_4
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_4";

                inline auto get() noexcept
                { return get_bits(_cpuid_edx(addr), mask) >> from; }
            }
        }
    }

    namespace processor_string_2
    {
        constexpr const auto addr = 0x80000003ULL;
        constexpr const auto name = "processor_string_2";

        namespace eax
        {
            namespace part_1
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_1";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }

        namespace ebx
        {
            namespace part_2
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_2";

                inline auto get() noexcept
                { return get_bits(_cpuid_ebx(addr), mask) >> from; }
            }
        }

        namespace ecx
        {
            namespace part_3
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_3";

                inline auto get() noexcept
                { return get_bits(_cpuid_ecx(addr), mask) >> from; }
            }
        }

        namespace edx
        {
            namespace part_4
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_4";

                inline auto get() noexcept
                { return get_bits(_cpuid_edx(addr), mask) >> from; }
            }
        }
    }

    namespace processor_string_3
    {
        constexpr const auto addr = 0x80000004ULL;
        constexpr const auto name = "processor_string_3";

        namespace eax
        {
            namespace part_1
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_1";

                inline auto get() noexcept
                { return get_bits(_cpuid_eax(addr), mask) >> from; }
            }
        }

        namespace ebx
        {
            namespace part_2
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_2";

                inline auto get() noexcept
                { return get_bits(_cpuid_ebx(addr), mask) >> from; }
            }
        }

        namespace ecx
        {
            namespace part_3
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_3";

                inline auto get() noexcept
                { return get_bits(_cpuid_ecx(addr), mask) >> from; }
            }
        }

        namespace edx
        {
            namespace part_4
            {
                constexpr const auto mask = 0xFFFFFFFFULL;
                constexpr const auto from = 0;
                constexpr const auto name = "part_4";

                inline auto get() noexcept
                { return get_bits(_cpuid_edx(addr), mask) >> from; }
            }
        }
    }
}
}

// *INDENT-ON*

#endif

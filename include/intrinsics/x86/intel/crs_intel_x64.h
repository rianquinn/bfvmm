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

#ifndef CRS_INTEL_X64_H
#define CRS_INTEL_X64_H

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

extern "C" EXPORT_INTRINSICS uint64_t _read_cr0(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cr0(uint64_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint64_t _read_cr2(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cr2(uint64_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint64_t _read_cr3(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cr3(uint64_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint64_t _read_cr4(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cr4(uint64_t val) noexcept;

extern "C" EXPORT_INTRINSICS uint64_t _read_cr8(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_cr8(uint64_t val) noexcept;

// *INDENT-OFF*

namespace intel_x64
{
namespace cr0
{
    constexpr const auto name = "cr0";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr0(); }

    inline void set(value_type val) noexcept
    { _write_cr0(val); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }

    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto is_enabled()
        { return is_bit_set(_read_cr0(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr0(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr0(set_bit(_read_cr0(), from)); }

        inline auto enable(value_type cr)
        { _write_cr0(set_bit(cr, from)); }

        inline void disable()
        { _write_cr0(clear_bit(_read_cr0(), from)); }

        inline auto disable(value_type cr)
        { _write_cr0(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        protection_enable::dump(level);
        monitor_coprocessor::dump(level);
        emulation::dump(level);
        task_switched::dump(level);
        extension_type::dump(level);
        numeric_error::dump(level);
        write_protect::dump(level);
        alignment_mask::dump(level);
        not_write_through::dump(level);
        cache_disable::dump(level);
        paging::dump(level);
    }
}

namespace cr2
{
    constexpr const auto name = "cr2";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr2(); }

    inline void set(value_type val) noexcept
    { _write_cr2(val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace cr3
{
    constexpr const auto name = "cr3";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr3(); }

    inline void set(value_type val) noexcept
    { _write_cr3(val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

namespace cr4
{
    constexpr const auto name = "cr4";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr4(); }

    inline void set(value_type val) noexcept
    { _write_cr4(val); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(_read_cr4(), from); }

        inline auto is_enabled(value_type cr)
        { return is_bit_set(cr, from); }

        inline auto is_disabled()
        { return is_bit_cleared(_read_cr4(), from); }

        inline auto is_disabled(value_type cr)
        { return is_bit_cleared(cr, from); }

        inline void enable()
        { _write_cr4(set_bit(_read_cr4(), from)); }

        inline auto enable(value_type cr)
        { _write_cr4(set_bit(cr, from)); }

        inline void disable()
        { _write_cr4(clear_bit(_read_cr4(), from)); }

        inline auto disable(value_type cr)
        { _write_cr4(clear_bit(cr, from)); }

        inline void dump(int level)
        { bfdebug_subbool(level, name, is_enabled()); }
    }

    inline void dump(int level)
    {
        bfdebug_nhex(level, name, get());
        v8086_mode_extensions::dump(level);
        protected_mode_virtual_interrupts::dump(level);
        time_stamp_disable::dump(level);
        debugging_extensions::dump(level);
        page_size_extensions::dump(level);
        physical_address_extensions::dump(level);
        machine_check_enable::dump(level);
        page_global_enable::dump(level);
        performance_monitor_counter_enable::dump(level);
        osfxsr::dump(level);
        osxmmexcpt::dump(level);
        vmx_enable_bit::dump(level);
        smx_enable_bit::dump(level);
        fsgsbase_enable_bit::dump(level);
        pcid_enable_bit::dump(level);
        osxsave::dump(level);
        smep_enable_bit::dump(level);
        smap_enable_bit::dump(level);
        protection_key_enable_bit::dump(level);
    }
}

namespace cr8
{
    constexpr const auto name = "cr8";

    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_cr8(); }

    inline void set(value_type val) noexcept
    { _write_cr8(val); }

    inline void dump(int level)
    { bfdebug_nhex(level, name, get()); }
}

}

// *INDENT-ON*

#endif

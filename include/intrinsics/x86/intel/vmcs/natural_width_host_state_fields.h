//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_NATURAL_WIDTH_HOST_STATE_FIELDS_H
#define VMCS_INTEL_X64_NATURAL_WIDTH_HOST_STATE_FIELDS_H

#include <intrinsics/x86/intel/vmcs/helpers.h>

/// Intel x86_64 VMCS Natural-Width Host-State Fields
///
/// The following provides the interface for the natural-width host-state VMCS
/// fields as defined in Appendix B.4.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_cr0
{
    constexpr const auto addr = 0x0000000000006C00ULL;
    constexpr const auto name = "host_cr0";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace protection_enable
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "protection_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace monitor_coprocessor
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "monitor_coprocessor";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace emulation
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "emulation";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace task_switched
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "task_switched";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace extension_type
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "extension_type";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace numeric_error
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "numeric_error";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace write_protect
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "write_protect";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace alignment_mask
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "alignment_mask";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace not_write_through
    {
        constexpr const auto mask = 0x0000000020000000ULL;
        constexpr const auto from = 29;
        constexpr const auto name = "not_write_through";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace cache_disable
    {
        constexpr const auto mask = 0x0000000040000000ULL;
        constexpr const auto from = 30;
        constexpr const auto name = "cache_disable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace paging
    {
        constexpr const auto mask = 0x0000000080000000ULL;
        constexpr const auto from = 31;
        constexpr const auto name = "paging";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
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

namespace host_cr3
{
    constexpr const auto addr = 0x0000000000006C02ULL;
    constexpr const auto name = "host_cr3";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_cr4
{
    constexpr const auto addr = 0x0000000000006C04ULL;
    constexpr const auto name = "host_cr4";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace v8086_mode_extensions
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "v8086_mode_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace protected_mode_virtual_interrupts
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "protected_mode_virtual_interrupts";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace time_stamp_disable
    {
        constexpr const auto mask = 0x0000000000000004ULL;
        constexpr const auto from = 2;
        constexpr const auto name = "time_stamp_disable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace debugging_extensions
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "debugging_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace page_size_extensions
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "page_size_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace physical_address_extensions
    {
        constexpr const auto mask = 0x0000000000000020ULL;
        constexpr const auto from = 5;
        constexpr const auto name = "physical_address_extensions";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace machine_check_enable
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "machine_check_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace page_global_enable
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "page_global_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace performance_monitor_counter_enable
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "performance_monitor_counter_enable";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace osfxsr
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "osfxsr";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace osxmmexcpt
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "osxmmexcpt";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace vmx_enable_bit
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "vmx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace smx_enable_bit
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "smx_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace fsgsbase_enable_bit
    {
        constexpr const auto mask = 0x0000000000010000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "fsgsbase_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace pcid_enable_bit
    {
        constexpr const auto mask = 0x0000000000020000ULL;
        constexpr const auto from = 17;
        constexpr const auto name = "pcid_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace osxsave
    {
        constexpr const auto mask = 0x0000000000040000ULL;
        constexpr const auto from = 18;
        constexpr const auto name = "osxsave";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace smep_enable_bit
    {
        constexpr const auto mask = 0x0000000000100000ULL;
        constexpr const auto from = 20;
        constexpr const auto name = "smep_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace smap_enable_bit
    {
        constexpr const auto mask = 0x0000000000200000ULL;
        constexpr const auto from = 21;
        constexpr const auto name = "smap_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    namespace protection_key_enable_bit
    {
        constexpr const auto mask = 0x0000000000400000ULL;
        constexpr const auto from = 22;
        constexpr const auto name = "protection_key_enable_bit";

        inline auto is_enabled()
        { return is_bit_set(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_enabled(value_type field)
        { return is_bit_set(field, from); }

        inline auto is_enabled_if_exists(bool verbose = false)
        { return is_bit_set(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline auto is_disabled()
        { return is_bit_cleared(get_vmcs_field(addr, name, exists()), from); }

        inline auto is_disabled(value_type field)
        { return is_bit_cleared(field, from); }

        inline auto is_disabled_if_exists(bool verbose = false)
        { return is_bit_cleared(get_vmcs_field_if_exists(addr, name, verbose, exists()), from); }

        inline void enable()
        { set_vmcs_field_bit(addr, from, name, exists()); }

        inline auto enable(value_type field)
        { return set_bit(field, from); }

        inline void enable_if_exists(bool verbose = false)
        { set_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void disable()
        { clear_vmcs_field_bit(addr, from, name, exists()); }

        inline auto disable(value_type field)
        { return clear_bit(field, from); }

        inline void disable_if_exists(bool verbose = false)
        { clear_vmcs_field_bit_if_exists(addr, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subbool(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
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

namespace host_fs_base
{
    constexpr const auto addr = 0x0000000000006C06ULL;
    constexpr const auto name = "host_fs_base";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_gs_base
{
    constexpr const auto addr = 0x0000000000006C08ULL;
    constexpr const auto name = "host_gs_base";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_tr_base
{
    constexpr const auto addr = 0x0000000000006C0AULL;
    constexpr const auto name = "host_tr_base";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_gdtr_base
{
    constexpr const auto addr = 0x0000000000006C0CULL;
    constexpr const auto name = "host_gdtr_base";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_idtr_base
{
    constexpr const auto addr = 0x0000000000006C0EULL;
    constexpr const auto name = "host_idtr_base";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_ia32_sysenter_esp
{
    constexpr const auto addr = 0x0000000000006C10ULL;
    constexpr const auto name = "host_ia32_sysenter_esp";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_ia32_sysenter_eip
{
    constexpr const auto addr = 0x0000000000006C12ULL;
    constexpr const auto name = "host_ia32_sysenter_eip";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_rsp
{
    constexpr const auto addr = 0x0000000000006C14ULL;
    constexpr const auto name = "host_rsp";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

namespace host_rip
{
    constexpr const auto addr = 0x0000000000006C16ULL;
    constexpr const auto name = "host_rip";

    inline bool exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level)
    { dump_vmcs_nhex(level); }
}

}
}

// *INDENT-ON*

#endif

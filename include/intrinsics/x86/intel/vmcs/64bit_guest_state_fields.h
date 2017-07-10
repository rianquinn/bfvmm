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

#ifndef VMCS_INTEL_X64_64BIT_GUEST_STATE_FIELDS_H
#define VMCS_INTEL_X64_64BIT_GUEST_STATE_FIELDS_H

#include <intrinsics/x86/intel/vmcs/helpers.h>

/// Intel x86_64 VMCS 64-bit Guest-State Fields
///
/// The following provides the interface for the 64-bit guest-state VMCS
/// fields as defined in Appendix B.2.3, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace vmcs_link_pointer
{
    constexpr const auto addr = 0x0000000000002800ULL;
    constexpr const auto name = "vmcs_link_pointer";

    inline auto exists()
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

namespace guest_ia32_debugctl
{
    constexpr const auto addr = 0x0000000000002802ULL;
    constexpr const auto name = "guest_ia32_debugctl";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace lbr
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "lbr";

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

    namespace btf
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "btf";

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

    namespace tr
    {
        constexpr const auto mask = 0x0000000000000040ULL;
        constexpr const auto from = 6;
        constexpr const auto name = "tr";

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

    namespace bts
    {
        constexpr const auto mask = 0x0000000000000080ULL;
        constexpr const auto from = 7;
        constexpr const auto name = "bts";

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

    namespace btint
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "btint";

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

    namespace bt_off_os
    {
        constexpr const auto mask = 0x0000000000000200ULL;
        constexpr const auto from = 9;
        constexpr const auto name = "bt_off_os";

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

    namespace bt_off_user
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "bt_off_user";

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

    namespace freeze_lbrs_on_pmi
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "freeze_lbrs_on_pmi";

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
    namespace freeze_perfmon_on_pmi
    {
        constexpr const auto mask = 0x0000000000001000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "freeze_perfmon_on_pmi";

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

    namespace enable_uncore_pmi
    {
        constexpr const auto mask = 0x0000000000002000ULL;
        constexpr const auto from = 13;
        constexpr const auto name = "enable_uncore_pmi";

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

    namespace freeze_while_smm
    {
        constexpr const auto mask = 0x0000000000004000ULL;
        constexpr const auto from = 14;
        constexpr const auto name = "freeze_while_smm";

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

    namespace rtm_debug
    {
        constexpr const auto mask = 0x0000000000008000ULL;
        constexpr const auto from = 15;
        constexpr const auto name = "rtm_debug";

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

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFF003CULL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
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
        reserved::dump(level);
    }
}

namespace guest_ia32_pat
{
    constexpr const auto addr = 0x0000000000002804ULL;
    constexpr const auto name = "guest_ia32_pat";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::is_allowed1() ||
               msrs::ia32_vmx_true_exit_ctls::save_ia32_pat::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace pa0
    {
        constexpr const auto mask = 0x00000000000000FFULL;
        constexpr const auto from = 0;
        constexpr const auto name = "pa0";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000007ULL;
            constexpr const auto from = 0;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00000000000000F8ULL;
            constexpr const auto from = 3;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa1
    {
        constexpr const auto mask = 0x000000000000FF00ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "pa1";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000000700ULL;
            constexpr const auto from = 8;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x000000000000F800ULL;
            constexpr const auto from = 11;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa2
    {
        constexpr const auto mask = 0x0000000000FF0000ULL;
        constexpr const auto from = 16;
        constexpr const auto name = "pa2";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000000070000ULL;
            constexpr const auto from = 16;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x0000000000F80000ULL;
            constexpr const auto from = 19;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa3
    {
        constexpr const auto mask = 0x00000000FF000000ULL;
        constexpr const auto from = 24;
        constexpr const auto name = "pa3";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000007000000ULL;
            constexpr const auto from = 24;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00000000F8000000ULL;
            constexpr const auto from = 27;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa4
    {
        constexpr const auto mask = 0x000000FF00000000ULL;
        constexpr const auto from = 32;
        constexpr const auto name = "pa4";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000000700000000ULL;
            constexpr const auto from = 32;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x000000F800000000ULL;
            constexpr const auto from = 35;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa5
    {
        constexpr const auto mask = 0x0000FF0000000000ULL;
        constexpr const auto from = 40;
        constexpr const auto name = "pa5";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0000070000000000ULL;
            constexpr const auto from = 40;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x0000F80000000000ULL;
            constexpr const auto from = 43;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa6
    {
        constexpr const auto mask = 0x00FF000000000000ULL;
        constexpr const auto from = 48;
        constexpr const auto name = "pa6";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0007000000000000ULL;
            constexpr const auto from = 48;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0x00F8000000000000ULL;
            constexpr const auto from = 51;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    namespace pa7
    {
        constexpr const auto mask = 0xFF00000000000000ULL;
        constexpr const auto from = 56;
        constexpr const auto name = "pa7";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        namespace memory_type
        {
            constexpr const auto mask = 0x0700000000000000ULL;
            constexpr const auto from = 56;
            constexpr const auto name = "memory_type";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        namespace reserved
        {
            constexpr const auto mask = 0xF800000000000000ULL;
            constexpr const auto from = 59;
            constexpr const auto name = "reserved";

            inline auto get()
            { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

            inline auto get(value_type field)
            { return get_bits(field, mask) >> from; }

            inline auto get_if_exists(bool verbose = false)
            { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

            inline void set(value_type val)
            { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

            inline auto set(value_type field, value_type val)
            { return set_bits(field, mask, (val << from)); }

            inline void set_if_exists(value_type val, bool verbose = false)
            { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

            inline void dump(int level)
            { dump_vmcs_subnhex(level); }
        }

        inline void dump(int level)
        {
            dump_vmcs_nhex(level);
            memory_type::dump(level);
            reserved::dump(level);
        }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        pa0::dump(level);
        pa1::dump(level);
        pa2::dump(level);
        pa3::dump(level);
        pa4::dump(level);
        pa5::dump(level);
        pa6::dump(level);
        pa7::dump(level);
    }
}

namespace guest_ia32_efer
{
    constexpr const auto addr = 0x0000000000002806ULL;
    constexpr const auto name = "guest_ia32_efer";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::is_allowed1() ||
               msrs::ia32_vmx_true_exit_ctls::save_ia32_efer::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace sce
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "sce";

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

    namespace lme
    {
        constexpr const auto mask = 0x0000000000000100ULL;
        constexpr const auto from = 8;
        constexpr const auto name = "lme";

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

    namespace lma
    {
        constexpr const auto mask = 0x0000000000000400ULL;
        constexpr const auto from = 10;
        constexpr const auto name = "lma";

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

    namespace nxe
    {
        constexpr const auto mask = 0x0000000000000800ULL;
        constexpr const auto from = 11;
        constexpr const auto name = "nxe";

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

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF2FEULL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        sce::dump(level);
        lme::dump(level);
        lma::dump(level);
        nxe::dump(level);
        reserved::dump(level);
    }
}

namespace guest_ia32_perf_global_ctrl
{
    constexpr const auto addr = 0x0000000000002808ULL;
    constexpr const auto name = "guest_ia32_perf_global_ctrl";

    inline auto exists()
    { return msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::is_allowed1(); }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace reserved
    {
        constexpr const auto mask = 0xFFFFFFF8FFFFFFFCULL;
        constexpr const auto from = 0;

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        reserved::dump(level);
    }
}

namespace guest_pdpte0
{
    constexpr const auto addr = 0x000000000000280AULL;
    constexpr const auto name = "guest_pdpte0";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "present";

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

    namespace reserved
    {
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pwt";

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

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pcd";

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

    namespace page_directory_addr
    {
        constexpr const auto from = 12;
        constexpr const auto name = "page_directory_addr";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        present::dump(level);
        reserved::dump(level);
        pwt::dump(level);
        pcd::dump(level);
        page_directory_addr::dump(level);
    }
}

namespace guest_pdpte1
{
    constexpr const auto addr = 0x000000000000280CULL;
    constexpr const auto name = "guest_pdpte1";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "present";

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

    namespace reserved
    {
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pwt";

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

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pcd";

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

    namespace page_directory_addr
    {
        constexpr const auto from = 12;
        constexpr const auto name = "page_directory_addr";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        present::dump(level);
        reserved::dump(level);
        pwt::dump(level);
        pcd::dump(level);
        page_directory_addr::dump(level);
    }
}

namespace guest_pdpte2
{
    constexpr const auto addr = 0x000000000000280EULL;
    constexpr const auto name = "guest_pdpte2";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "present";

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

    namespace reserved
    {
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pwt";

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

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pcd";

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

    namespace page_directory_addr
    {
        constexpr const auto from = 12;
        constexpr const auto name = "page_directory_addr";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        present::dump(level);
        reserved::dump(level);
        pwt::dump(level);
        pcd::dump(level);
        page_directory_addr::dump(level);
    }
}

namespace guest_pdpte3
{
    constexpr const auto addr = 0x0000000000002810ULL;
    constexpr const auto name = "guest_pdpte3";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace present
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "present";

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

    namespace reserved
    {
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3;
        constexpr const auto name = "pwt";

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

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4;
        constexpr const auto name = "pcd";

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

    namespace page_directory_addr
    {
        constexpr const auto from = 12;
        constexpr const auto name = "page_directory_addr";

        inline auto mask()
        { return (0xFFFFFFFFFFFFFFFFULL << x64::cpuid::addr_size::phys::get() | 0x1E6ULL); }

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask()) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask()) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask()) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask(), from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask(), (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask(), from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        present::dump(level);
        reserved::dump(level);
        pwt::dump(level);
        pcd::dump(level);
        page_directory_addr::dump(level);
    }
}

namespace guest_ia32_bndcfgs
{
    constexpr const auto addr = 0x0000000000002812ULL;
    constexpr const auto name = "guest_ia32_bndcfgs";

    inline auto exists()
    {
        return msrs::ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::is_allowed1() ||
               msrs::ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    namespace en
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0;
        constexpr const auto name = "en";

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

    namespace bndpreserve
    {
        constexpr const auto mask = 0x0000000000000002ULL;
        constexpr const auto from = 1;
        constexpr const auto name = "bndpreserve";

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

    namespace reserved
    {
        constexpr const auto mask = 0x0000000000000FFCULL;
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    namespace base_addr_of_bnd_directory
    {
        constexpr const auto mask = 0xFFFFFFFFFFFFF000ULL;
        constexpr const auto from = 12;
        constexpr const auto name = "base_addr_of_bnd_directory";

        inline auto get()
        { return get_bits(get_vmcs_field(addr, name, exists()), mask) >> from; }

        inline auto get(value_type field)
        { return get_bits(field, mask) >> from; }

        inline auto get_if_exists(bool verbose = false)
        { return get_bits(get_vmcs_field_if_exists(addr, name, verbose, exists()), mask) >> from; }

        inline void set(value_type val)
        { set_vmcs_field_bits(val, addr, mask, from, name, exists()); }

        inline auto set(value_type field, value_type val)
        { return set_bits(field, mask, (val << from)); }

        inline void set_if_exists(value_type val, bool verbose = false)
        { set_vmcs_field_bits_if_exists(val, addr, mask, from, name, verbose, exists()); }

        inline void dump(int level)
        { dump_vmcs_subnhex(level); }
    }

    inline void dump(int level)
    {
        dump_vmcs_nhex(level);
        en::dump(level);
        bndpreserve::dump(level);
        reserved::dump(level);
        base_addr_of_bnd_directory::dump(level);
    }
}

}
}

// *INDENT-ON*

#endif

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

#ifndef RFLAGS_X64_H
#define RFLAGS_X64_H

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

extern "C" EXPORT_INTRINSICS uint64_t _read_rflags(void) noexcept;
extern "C" EXPORT_INTRINSICS void _write_rflags(uint64_t val) noexcept;

// *INDENT-OFF*

namespace x64
{
namespace rflags
{

using value_type = uint64_t;

constexpr const auto name = "rflags";

inline auto get() noexcept
{ return _read_rflags(); }

inline void set(value_type rflags) noexcept
{ _write_rflags(rflags); }

namespace carry_flag
{
    constexpr const auto mask = 0x0000000000000001ULL;
    constexpr const auto from = 0;
    constexpr const auto name = "carry_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace parity_flag
{
    constexpr const auto mask = 0x0000000000000004ULL;
    constexpr const auto from = 2;
    constexpr const auto name = "parity_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace auxiliary_carry_flag
{
    constexpr const auto mask = 0x0000000000000010ULL;
    constexpr const auto from = 4;
    constexpr const auto name = "auxiliary_carry_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace zero_flag
{
    constexpr const auto mask = 0x0000000000000040ULL;
    constexpr const auto from = 6;
    constexpr const auto name = "zero_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace sign_flag
{
    constexpr const auto mask = 0x0000000000000080ULL;
    constexpr const auto from = 7;
    constexpr const auto name = "sign_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace trap_flag
{
    constexpr const auto mask = 0x0000000000000100ULL;
    constexpr const auto from = 8;
    constexpr const auto name = "trap_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace interrupt_enable_flag
{
    constexpr const auto mask = 0x0000000000000200ULL;
    constexpr const auto from = 9;
    constexpr const auto name = "interrupt_enable_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace direction_flag
{
    constexpr const auto mask = 0x0000000000000400ULL;
    constexpr const auto from = 10;
    constexpr const auto name = "direction_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace overflow_flag
{
    constexpr const auto mask = 0x0000000000000800ULL;
    constexpr const auto from = 11;
    constexpr const auto name = "overflow_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace privilege_level
{
    constexpr const auto mask = 0x0000000000003000ULL;
    constexpr const auto from = 12;
    constexpr const auto name = "privilege_level";

    inline auto get() noexcept
    { return get_bits(_read_rflags(), mask) >> from; }

    inline auto get(value_type rflags) noexcept
    { return get_bits(rflags, mask) >> from; }

    inline void set(value_type val) noexcept
    { _write_rflags(set_bits(_read_rflags(), mask, val << from)); }

    inline auto set(value_type rflags, value_type val) noexcept
    { return set_bits(rflags, mask, val << from); }

    inline void dump(int level)
    { bfdebug_subnhex(level, name, get()); }
}

namespace nested_task
{
    constexpr const auto mask = 0x0000000000004000ULL;
    constexpr const auto from = 14;
    constexpr const auto name = "nested_task";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace resume_flag
{
    constexpr const auto mask = 0x0000000000010000ULL;
    constexpr const auto from = 16;
    constexpr const auto name = "resume_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace virtual_8086_mode
{
    constexpr const auto mask = 0x0000000000020000ULL;
    constexpr const auto from = 17;
    constexpr const auto name = "virtual_8086_mode";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace alignment_check_access_control
{
    constexpr const auto mask = 0x0000000000040000ULL;
    constexpr const auto from = 18;
    constexpr const auto name = "alignment_check_access_control";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace virtual_interupt_flag
{
    constexpr const auto mask = 0x0000000000080000ULL;
    constexpr const auto from = 19;
    constexpr const auto name = "virtual_interupt_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace virtual_interupt_pending
{
    constexpr const auto mask = 0x0000000000100000ULL;
    constexpr const auto from = 20;
    constexpr const auto name = "virtual_interupt_pending";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

namespace id_flag
{
    constexpr const auto mask = 0x0000000000200000ULL;
    constexpr const auto from = 21;
    constexpr const auto name = "id_flag";

    inline auto is_enabled()
    { return is_bit_set(_read_rflags(), from); }

    inline auto is_enabled(value_type rflags)
    { return is_bit_set(rflags, from); }

    inline auto is_disabled()
    { return is_bit_cleared(_read_rflags(), from); }

    inline auto is_disabled(value_type rflags)
    { return is_bit_cleared(rflags, from); }

    inline void enable()
    { _write_rflags(set_bit(_read_rflags(), from)); }

    inline auto enable(value_type rflags)
    { return set_bit(rflags, from); }

    inline void disable()
    { _write_rflags(clear_bit(_read_rflags(), from)); }

    inline auto disable(value_type rflags)
    { return clear_bit(rflags, from); }

    inline void dump(int level)
    { bfdebug_subbool(level, name, is_enabled()); }
}

inline void dump(int level)
{
    bfdebug_nhex(level, name, get());
    carry_flag::dump(level);
    parity_flag::dump(level);
    auxiliary_carry_flag::dump(level);
    zero_flag::dump(level);
    sign_flag::dump(level);
    trap_flag::dump(level);
    interrupt_enable_flag::dump(level);
    direction_flag::dump(level);
    overflow_flag::dump(level);
    privilege_level::dump(level);
    nested_task::dump(level);
    resume_flag::dump(level);
    virtual_8086_mode::dump(level);
    alignment_check_access_control::dump(level);
    virtual_interupt_flag::dump(level);
    virtual_interupt_pending::dump(level);
    id_flag::dump(level);
}

}
}

// *INDENT-ON*

#endif

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

#ifndef RDTSC_X64_H
#define RDTSC_X64_H

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

extern "C" EXPORT_INTRINSICS uint64_t _read_tsc(void) noexcept;
extern "C" EXPORT_INTRINSICS uint64_t _read_tscp(void) noexcept;

// *INDENT-OFF*

namespace x64
{

namespace read_tsc
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_tsc(); }
}

namespace read_tscp
{
    using value_type = uint64_t;

    inline auto get() noexcept
    { return _read_tscp(); }
}

}

// *INDENT-ON*

#endif

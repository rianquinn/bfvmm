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

namespace x64
{
namespace cpuid
{
namespace intel
{
namespace cache_tlb_info
{
constexpr const auto addr = 0x00000002ULL;
constexpr const auto name = "cache_tlb_info";

namespace eax
{
namespace info
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "info";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace info
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "info";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace info
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "info";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace info
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "info";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace serial_num
{
constexpr const auto addr = 0x00000003ULL;
constexpr const auto name = "serial_num";

namespace ecx
{
namespace bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "bits";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "bits";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace cache_parameters
{
constexpr const auto addr = 0x00000004ULL;
constexpr const auto name = "cache_parameters";

namespace eax
{
namespace cache_type
{
constexpr const auto mask = 0x0000001FULL;
constexpr const auto from = 0;
constexpr const auto name = "cache_type";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace cache_level
{
constexpr const auto mask = 0x000000E0ULL;
constexpr const auto from = 5;
constexpr const auto name = "cache_level";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace self_init_level
{
constexpr const auto mask = 0x00000100ULL;
constexpr const auto from = 8;
constexpr const auto name = "self_init_level";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace fully_associative
{
constexpr const auto mask = 0x00000200ULL;
constexpr const auto from = 9;
constexpr const auto name = "fully_associative";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace max_ids_logical
{
constexpr const auto mask = 0x03FFC000ULL;
constexpr const auto from = 14;
constexpr const auto name = "max_ids_logical";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace max_ids_physical
{
constexpr const auto mask = 0xFC000000ULL;
constexpr const auto from = 26;
constexpr const auto name = "max_ids_physical";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace l
{
constexpr const auto mask = 0x00000FFFULL;
constexpr const auto from = 0;
constexpr const auto name = "l";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}

namespace p
{
constexpr const auto mask = 0x003FF000ULL;
constexpr const auto from = 12;
constexpr const auto name = "p";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}

namespace w
{
constexpr const auto mask = 0xFFC00000ULL;
constexpr const auto from = 22;
constexpr const auto name = "w";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace num_sets
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "num_sets";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace wbinvd_invd
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "wbinvd_invd";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace cache_inclusiveness
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "cache_inclusiveness";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace complex_cache_indexing
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "complex_cache_indexing";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}
}
}

namespace monitor_mwait
{
constexpr const auto addr = 0x00000005ULL;
constexpr const auto name = "monitor_mwait";

namespace eax
{
namespace min_line_size
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "min_line_size";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace max_line_size
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_line_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace enum_mwait_extensions
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "enum_mwait_extensions";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace interrupt_break_event
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "interrupt_break_event";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}

namespace edx
{
namespace num_c0
{
constexpr const auto mask = 0x0000000FULL;
constexpr const auto from = 0;
constexpr const auto name = "num_c0";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c1
{
constexpr const auto mask = 0x000000F0ULL;
constexpr const auto from = 4;
constexpr const auto name = "num_c1";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c2
{
constexpr const auto mask = 0x00000F00ULL;
constexpr const auto from = 8;
constexpr const auto name = "num_c2";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c3
{
constexpr const auto mask = 0x0000F000ULL;
constexpr const auto from = 12;
constexpr const auto name = "num_c3";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c4
{
constexpr const auto mask = 0x000F0000ULL;
constexpr const auto from = 16;
constexpr const auto name = "num_c4";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c5
{
constexpr const auto mask = 0x00F00000ULL;
constexpr const auto from = 20;
constexpr const auto name = "num_c5";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c6
{
constexpr const auto mask = 0x0F000000ULL;
constexpr const auto from = 24;
constexpr const auto name = "num_c6";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace num_c7
{
constexpr const auto mask = 0xF0000000ULL;
constexpr const auto from = 28;
constexpr const auto name = "num_c7";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace therm_power_management
{
constexpr const auto addr = 0x00000006ULL;
constexpr const auto name = "therm_power_management";

namespace eax
{
namespace temp_sensor
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "temp_sensor";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace intel_turbo
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "intel_turbo";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace arat
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "arat";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace pln
{
constexpr const auto mask = 0x00000010ULL;
constexpr const auto from = 4;
constexpr const auto name = "pln";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace ecmd
{
constexpr const auto mask = 0x00000020ULL;
constexpr const auto from = 5;
constexpr const auto name = "ecmd";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace ptm
{
constexpr const auto mask = 0x00000040ULL;
constexpr const auto from = 6;
constexpr const auto name = "ptm";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hwp
{
constexpr const auto mask = 0x00000080ULL;
constexpr const auto from = 7;
constexpr const auto name = "hwp";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hwp_notification
{
constexpr const auto mask = 0x00000100ULL;
constexpr const auto from = 8;
constexpr const auto name = "hwp_notification";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hwp_activity_window
{
constexpr const auto mask = 0x00000200ULL;
constexpr const auto from = 9;
constexpr const auto name = "hwp_activity_window";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hwp_energy_perf
{
constexpr const auto mask = 0x00000400ULL;
constexpr const auto from = 10;
constexpr const auto name = "hwp_energy_perf";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hwp_package_request
{
constexpr const auto mask = 0x00000800ULL;
constexpr const auto from = 11;
constexpr const auto name = "hwp_package_request";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace hdc
{
constexpr const auto mask = 0x00002000ULL;
constexpr const auto from = 13;
constexpr const auto name = "hdc";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}
}

namespace ebx
{
namespace num_interrupts
{
constexpr const auto mask = 0x0000000FULL;
constexpr const auto from = 0;
constexpr const auto name = "num_interrupts";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace hardware_feedback
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "hardware_feedback";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace energy_perf_bias
{
constexpr const auto mask = 0x00000008ULL;
constexpr const auto from = 3;
constexpr const auto name = "energy_perf_bias";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}
}

namespace access_cache
{
constexpr const auto addr = 0x00000009ULL;
constexpr const auto name = "access_cache";

namespace eax
{
namespace ia32_platform_dca_cap
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "ia32_platform_dca_cap";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}
}

namespace topology_enumeration
{
constexpr const auto addr = 0x0000000BULL;
constexpr const auto name = "topology_enumeration";

namespace eax
{
namespace x2apic_shift
{
constexpr const auto mask = 0x0000001FULL;
constexpr const auto from = 0;
constexpr const auto name = "x2apic_shift";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace num_processors
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "num_processors";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace level_number
{
constexpr const auto mask = 0x000000FFULL;
constexpr const auto from = 0;
constexpr const auto name = "level_number";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}

namespace level_type
{
constexpr const auto mask = 0x0000FF00ULL;
constexpr const auto from = 8;
constexpr const auto name = "level_type";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace x2apic_id
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "x2apic_id";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace extended_state_enum
{
constexpr const auto addr = 0x0000000DULL;
constexpr const auto name = "extended_state_enum";

namespace mainleaf
{
namespace eax
{
namespace supported_bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "supported_bits";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace max_size
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace max_size
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace supported_bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "supported_bits";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleaf0
{
namespace eax
{
namespace xsaveopt
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "xsaveopt";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace xsavec
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "xsavec";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace xgetbv
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "xgetbv";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace xsaves_xrstors
{
constexpr const auto mask = 0x00000008ULL;
constexpr const auto from = 3;
constexpr const auto name = "xsaves_xrstors";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}
}

namespace ebx
{
namespace xsave_size
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "xsave_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace supported_bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "supported_bits";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace supported_bits
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "supported_bits";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleafn
{
namespace eax
{
namespace save_area_size
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "save_area_size";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace save_area_offset
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "save_area_offset";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace n_supported
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "n_supported";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace location
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "location";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}
}
}

namespace intel_rdt
{
constexpr const auto addr = 0x0000000FULL;
constexpr const auto name = "intel_rdt";

namespace subleaf0
{
namespace ebx
{
namespace rmid_max_range
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "rmid_max_range";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace edx
{
namespace l3_rdt
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "l3_rdt";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}
}
}

namespace subleaf1
{
namespace ebx
{
namespace conversion_factor
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "conversion_factor";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace rmid_max_range
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "rmid_max_range";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace l3_occupancy
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "l3_occupancy";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace l3_total_bandwith
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "l3_total_bandwith";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace l3_local_bandwith
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "l3_local_bandwith";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}
}
}
}

namespace allocation_enumeration
{
constexpr const auto addr = 0x00000010ULL;
constexpr const auto name = "allocation_enumeration";

namespace subleaf0
{
namespace ebx
{
namespace l3_cache
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "l3_cache";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace l2_cache
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "l2_cache";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace mem_bandwidth
{
constexpr const auto mask = 0x00000008ULL;
constexpr const auto from = 3;
constexpr const auto name = "mem_bandwidth";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}
}
}

namespace subleaf1
{
namespace eax
{
namespace mask_length
{
constexpr const auto mask = 0x0000001FULL;
constexpr const auto from = 0;
constexpr const auto name = "mask_length";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace map
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "map";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace data_prio
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "data_prio";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}

namespace edx
{
namespace max_cos
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_cos";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleaf2
{
namespace eax
{
namespace mask_length
{
constexpr const auto mask = 0x0000001FULL;
constexpr const auto from = 0;
constexpr const auto name = "mask_length";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace map
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "map";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace edx
{
namespace max_cos
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_cos";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleaf3
{
namespace eax
{
namespace max_throttle
{
constexpr const auto mask = 0x00000FFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_throttle";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ecx
{
namespace linear
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "linear";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}

namespace edx
{
namespace max_cos
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_cos";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}
}

namespace intel_sgx
{
constexpr const auto addr = 0x00000012ULL;
constexpr const auto name = "intel_sgx";

namespace subleaf0
{
namespace eax
{
namespace sgx1
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "sgx1";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}

namespace sgx2
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "sgx2";

inline auto get() noexcept
{ return get_bit(_cpuid_eax(addr), from) != 0; }
}
}

namespace ebx
{
namespace miscselect
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "miscselect";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace edx
{
namespace mes_not64
{
constexpr const auto mask = 0x000000FFULL;
constexpr const auto from = 0;
constexpr const auto name = "mes_not64";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}

namespace mes_64
{
constexpr const auto mask = 0x0000FF00ULL;
constexpr const auto from = 8;
constexpr const auto name = "mes_64";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleaf1
{
namespace part1
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "part1";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace part2
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "part2";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}

namespace part3
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "part3";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}

namespace part4
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "part4";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}

namespace subleaf2
{
namespace eax
{
namespace subleaf_type
{
constexpr const auto mask = 0x0000000FULL;
constexpr const auto from = 0;
constexpr const auto name = "subleaf_type";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace address
{
constexpr const auto mask = 0xFFFFF000ULL;
constexpr const auto from = 12;
constexpr const auto name = "address";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace address
{
constexpr const auto mask = 0x000FFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "address";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace epc_property
{
constexpr const auto mask = 0x0000000FULL;
constexpr const auto from = 0;
constexpr const auto name = "epc_property";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}

namespace epc_size
{
constexpr const auto mask = 0xFFFFF000ULL;
constexpr const auto from = 12;
constexpr const auto name = "epc_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace epc_size
{
constexpr const auto mask = 0x000FFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "epc_size";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}
}

namespace trace_enumeration
{
constexpr const auto addr = 0x00000014ULL;
constexpr const auto name = "trace_enumeration";

namespace mainleaf
{
namespace eax
{
namespace max_subleaf
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_subleaf";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace ia32_rtit_ctlcr3filter
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "ia32_rtit_ctlcr3filter";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace configurable_psb
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "configurable_psb";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace ip_filtering
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "ip_filtering";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace mtc_timing_packet
{
constexpr const auto mask = 0x00000008ULL;
constexpr const auto from = 3;
constexpr const auto name = "mtc_timing_packet";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace ptwrite
{
constexpr const auto mask = 0x00000010ULL;
constexpr const auto from = 4;
constexpr const auto name = "ptwrite";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}

namespace power_event_trace
{
constexpr const auto mask = 0x00000020ULL;
constexpr const auto from = 5;
constexpr const auto name = "power_event_trace";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}
}

namespace ecx
{
namespace trading_enabled
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "trading_enabled";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace topa_entry
{
constexpr const auto mask = 0x00000002ULL;
constexpr const auto from = 1;
constexpr const auto name = "topa_entry";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace single_range_output
{
constexpr const auto mask = 0x00000004ULL;
constexpr const auto from = 2;
constexpr const auto name = "single_range_output";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace trace_transport
{
constexpr const auto mask = 0x00000008ULL;
constexpr const auto from = 3;
constexpr const auto name = "trace_transport";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace lip_values
{
constexpr const auto mask = 0x80000000ULL;
constexpr const auto from = 31;
constexpr const auto name = "lip_values";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}
}

namespace subleaf
{
namespace eax
{
namespace num_address_ranges
{
constexpr const auto mask = 0x00000007ULL;
constexpr const auto from = 0;
constexpr const auto name = "num_address_ranges";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace bitmap_mtc
{
constexpr const auto mask = 0xFFFF0000ULL;
constexpr const auto from = 16;
constexpr const auto name = "bitmap_mtc";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace bitmap_cycle_threshold
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "bitmap_cycle_threshold";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}

namespace bitmap_psb
{
constexpr const auto mask = 0xFFFF0000ULL;
constexpr const auto from = 16;
constexpr const auto name = "bitmap_psb";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}
}
}

namespace time_stamp_count
{
constexpr const auto addr = 0x00000015ULL;
constexpr const auto name = "time_stamp_count";

namespace eax
{
namespace tsc_denom
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "tsc_denom";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace tsc_numer
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "tsc_numer";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace nominal_freq
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "nominal_freq";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}
}

namespace processor_freq
{
constexpr const auto addr = 0x00000016ULL;
constexpr const auto name = "processor_freq";

namespace eax
{
namespace base_freq
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "base_freq";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace max_freq
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_freq";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace bus_freq
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "bus_freq";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}
}

namespace vendor_attribute
{
constexpr const auto addr = 0x00000017ULL;
constexpr const auto name = "vendor_attribute";

namespace mainleaf
{
namespace max_socid
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "max_socid";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}

namespace ebx
{
namespace soc_vendor
{
constexpr const auto mask = 0x0000FFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "soc_vendor";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}

namespace is_vendor_scheme
{
constexpr const auto mask = 0x00010000ULL;
constexpr const auto from = 16;
constexpr const auto name = "is_vendor_scheme";

inline auto get() noexcept
{ return get_bit(_cpuid_ebx(addr), from) != 0; }
}
}

namespace ecx
{
namespace project_id
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "project_id";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace stepping_id
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "stepping_id";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}

namespace subleaf1
{
namespace eax
{
namespace brand_string
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "brand_string";

inline auto get() noexcept
{ return get_bits(_cpuid_eax(addr), mask) >> from; }
}
}

namespace ebx
{
namespace brand_string
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "brand_string";

inline auto get() noexcept
{ return get_bits(_cpuid_ebx(addr), mask) >> from; }
}
}

namespace ecx
{
namespace brand_string
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "brand_string";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}

namespace edx
{
namespace brand_string
{
constexpr const auto mask = 0xFFFFFFFFULL;
constexpr const auto from = 0;
constexpr const auto name = "brand_string";

inline auto get() noexcept
{ return get_bits(_cpuid_edx(addr), mask) >> from; }
}
}
}
}

namespace ext_feature_info
{
constexpr const auto addr = 0x80000001ULL;
constexpr const auto name = "ext_feature_info";

namespace ecx
{
namespace lahf_sahf
{
constexpr const auto mask = 0x00000001ULL;
constexpr const auto from = 0;
constexpr const auto name = "lahf_sahf";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace lzcnt
{
constexpr const auto mask = 0x00000020ULL;
constexpr const auto from = 5;
constexpr const auto name = "lzcnt";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}

namespace prefetchw
{
constexpr const auto mask = 0x00000100ULL;
constexpr const auto from = 8;
constexpr const auto name = "prefetchw";

inline auto get() noexcept
{ return get_bit(_cpuid_ecx(addr), from) != 0; }
}
}

namespace edx
{
namespace syscall_sysret
{
constexpr const auto mask = 0x00000800ULL;
constexpr const auto from = 11;
constexpr const auto name = "syscall_sysret";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace execute_disable_bit
{
constexpr const auto mask = 0x00100000ULL;
constexpr const auto from = 20;
constexpr const auto name = "execute_disable_bit";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace pages_avail
{
constexpr const auto mask = 0x04000000ULL;
constexpr const auto from = 26;
constexpr const auto name = "pages_avail";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace rdtscp
{
constexpr const auto mask = 0x08000000ULL;
constexpr const auto from = 27;
constexpr const auto name = "rdtscp";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}

namespace intel_64
{
constexpr const auto mask = 0x20000000ULL;
constexpr const auto from = 29;
constexpr const auto name = "intel_64";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}
}
}

namespace l2_info
{
constexpr const auto addr = 0x80000006ULL;
constexpr const auto name = "l2_info";

namespace ecx
{
namespace line_size
{
constexpr const auto mask = 0x000000FFULL;
constexpr const auto from = 0;
constexpr const auto name = "line_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}

namespace l2_associativity
{
constexpr const auto mask = 0x0000F000ULL;
constexpr const auto from = 12;
constexpr const auto name = "l2_associativity";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}

namespace cache_size
{
constexpr const auto mask = 0xFFFF0000ULL;
constexpr const auto from = 16;
constexpr const auto name = "cache_size";

inline auto get() noexcept
{ return get_bits(_cpuid_ecx(addr), mask) >> from; }
}
}
}

namespace invariant_tsc
{
constexpr const auto addr = 0x80000007ULL;
constexpr const auto name = "invariant_tsc";

namespace edx
{
namespace available
{
constexpr const auto mask = 0x00000100ULL;
constexpr const auto from = 8;
constexpr const auto name = "available";

inline auto get() noexcept
{ return get_bit(_cpuid_edx(addr), from) != 0; }
}
}
}
}
}
}

#endif

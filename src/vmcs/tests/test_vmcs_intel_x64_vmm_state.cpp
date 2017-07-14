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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <bftypes.h>

#include <vmcs/vmcs_intel_x64_vmm_state.h>

#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#include <memory_manager/pat_x64.h>
#include <memory_manager/root_page_table_x64.h>

#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;

static uint64_t test_cr0;
static uint64_t test_cr3;
static uint64_t test_cr4;
static uint64_t test_ia32_efer_msr;

static std::map<uint32_t, uint32_t> g_ecx;
static std::map<uint32_t, uint32_t> g_ebx;

static uint32_t
test_cpuid_ecx(uint32_t addr) noexcept
{ return g_ecx[addr]; }

static uint32_t
test_cpuid_subebx(uint32_t addr, uint32_t leaf)
{
    bfignored(leaf);
    return g_ebx[addr];
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_cpuid_ecx).Do(test_cpuid_ecx);
    mocks.OnCallFunc(_cpuid_subebx).Do(test_cpuid_subebx);
}

static void
setup_vmm_state(MockRepository &mocks)
{
    setup_intrinsics(mocks);

    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_pt).Return(pt);
    mocks.OnCall(pt, root_page_table_x64::cr3).Return(test_cr3);

    test_cr0 = 0;
    test_cr0 |= intel_x64::cr0::protection_enable::mask;
    test_cr0 |= intel_x64::cr0::monitor_coprocessor::mask;
    test_cr0 |= intel_x64::cr0::extension_type::mask;
    test_cr0 |= intel_x64::cr0::numeric_error::mask;
    test_cr0 |= intel_x64::cr0::write_protect::mask;
    test_cr0 |= intel_x64::cr0::paging::mask;

    test_cr3 = 0x000000ABCDEF0000;

    test_cr4 = 0;
    test_cr4 |= intel_x64::cr4::v8086_mode_extensions::mask;
    test_cr4 |= intel_x64::cr4::protected_mode_virtual_interrupts::mask;
    test_cr4 |= intel_x64::cr4::time_stamp_disable::mask;
    test_cr4 |= intel_x64::cr4::debugging_extensions::mask;
    test_cr4 |= intel_x64::cr4::page_size_extensions::mask;
    test_cr4 |= intel_x64::cr4::physical_address_extensions::mask;
    test_cr4 |= intel_x64::cr4::machine_check_enable::mask;
    test_cr4 |= intel_x64::cr4::page_global_enable::mask;
    test_cr4 |= intel_x64::cr4::performance_monitor_counter_enable::mask;
    test_cr4 |= intel_x64::cr4::osfxsr::mask;
    test_cr4 |= intel_x64::cr4::osxsave::mask;
    test_cr4 |= intel_x64::cr4::osxmmexcpt::mask;
    test_cr4 |= intel_x64::cr4::vmx_enable_bit::mask;
    test_cr4 |= intel_x64::cr4::smep_enable_bit::mask;
    test_cr4 |= intel_x64::cr4::smap_enable_bit::mask;
}

TEST_CASE("vmcs: vmm_state_gdt_not_setup")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    auto cs_access_rights = (access_rights::ring0_cs_descriptor & 0xF0FFULL);
    auto ss_access_rights = (access_rights::ring0_ss_descriptor & 0xF0FFULL);
    auto fs_access_rights = (access_rights::ring0_fs_descriptor & 0xF0FFULL);
    auto gs_access_rights = (access_rights::ring0_gs_descriptor & 0xF0FFULL);
    auto tr_access_rights = (access_rights::ring0_tr_descriptor & 0xF0FFULL);

    vmcs_intel_x64_vmm_state state{};

    CHECK(g_gdt.access_rights(1) == cs_access_rights);
    CHECK(g_gdt.access_rights(2) == ss_access_rights);
    CHECK(g_gdt.access_rights(3) == fs_access_rights);
    CHECK(g_gdt.access_rights(4) == gs_access_rights);
    CHECK(g_gdt.access_rights(5) == tr_access_rights);

    CHECK(g_gdt.base(1) == 0);
    CHECK(g_gdt.base(2) == 0);
    CHECK(g_gdt.base(3) == 0);
    CHECK(g_gdt.base(4) == 0);
    CHECK(g_gdt.base(5) == bfrcast(gdt_x64::integer_pointer, &g_tss));

    CHECK(g_gdt.limit(1) == 0xFFFFFFFF);
    CHECK(g_gdt.limit(2) == 0xFFFFFFFF);
    CHECK(g_gdt.limit(3) == 0xFFFFFFFF);
    CHECK(g_gdt.limit(4) == 0xFFFFFFFF);
    CHECK(g_gdt.limit(5) == sizeof(g_tss));
}

TEST_CASE("vmcs: vmm_state_segment_registers")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs() == 1U << 3);
    CHECK(state.ss() == 2U << 3);
    CHECK(state.fs() == 3U << 3);
    CHECK(state.gs() == 4U << 3);
    CHECK(state.tr() == 5U << 3);
}

TEST_CASE("vmcs: vmm_state_control_registers")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    g_ebx[intel_x64::cpuid::extended_feature_flags::addr] = 0x00100080UL;
    g_ecx[intel_x64::cpuid::feature_information::addr] = 0x4000000UL;

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cr0() == test_cr0);
    CHECK(state.cr3() == test_cr3);
    CHECK(state.cr4() == test_cr4);
}

TEST_CASE("vmcs: vmm_state_rflags")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.rflags() == 0U);
}

TEST_CASE("vmcs: vmm_state_gdt_base")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.gdt_base() == g_gdt.base());
}

TEST_CASE("vmcs: vmm_state_idt_base")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.idt_base() == g_idt.base());
}

TEST_CASE("vmcs: vmm_state_gdt_limit")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.gdt_limit() == g_gdt.limit());
}

TEST_CASE("vmcs: vmm_state_idt_limit")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.idt_limit() == g_idt.limit());
}

TEST_CASE("vmcs: vmm_state_segment_registers_limit")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_limit() == g_gdt.limit(1U));
    CHECK(state.ss_limit() == g_gdt.limit(2U));
    CHECK(state.fs_limit() == g_gdt.limit(3U));
    CHECK(state.gs_limit() == g_gdt.limit(4U));
    CHECK(state.tr_limit() == g_gdt.limit(5U));
}

TEST_CASE("vmcs: vmm_state_segment_registers_access_rights")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_access_rights() == g_gdt.access_rights(1U));
    CHECK(state.ss_access_rights() == g_gdt.access_rights(2U));
    CHECK(state.fs_access_rights() == g_gdt.access_rights(3U));
    CHECK(state.gs_access_rights() == g_gdt.access_rights(4U));
    CHECK(state.tr_access_rights() == g_gdt.access_rights(5U));
}

TEST_CASE("vmcs: vmm_state_segment_registers_base")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};

    CHECK(state.cs_base() == g_gdt.base(1U));
    CHECK(state.ss_base() == g_gdt.base(2U));
    CHECK(state.fs_base() == g_gdt.base(3U));
    CHECK(state.gs_base() == g_gdt.base(4U));
    CHECK(state.tr_base() == g_gdt.base(5U));
}

TEST_CASE("vmcs: vmm_state_ia32_efer_msr")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    test_ia32_efer_msr = 0;
    test_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lme::mask;
    test_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lma::mask;
    test_ia32_efer_msr |= intel_x64::msrs::ia32_efer::nxe::mask;

    vmcs_intel_x64_vmm_state state{};
    CHECK(state.ia32_pat_msr() == pat::pat_value);
    CHECK(state.ia32_efer_msr() == test_ia32_efer_msr);
}

TEST_CASE("vmcs: vmm_state_dump")
{
    MockRepository mocks;
    setup_vmm_state(mocks);

    vmcs_intel_x64_vmm_state state{};
    CHECK_NOTHROW(state.dump());
}

#endif

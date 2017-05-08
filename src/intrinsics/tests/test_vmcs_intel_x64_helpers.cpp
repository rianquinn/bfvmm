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

#define CATCH_CONFIG_MAIN
#include <catch/catch.hpp>

TEST_CASE("test name goes here")
{
    CHECK(true);
}

//void
//intrinsics_ut::test_get_vmcs_field()
//{
//    constexpr const auto name = "field";
//    auto exists = true;
//
//    this->expect_exception([&] { get_vmcs_field(0U, name, !exists); }, ""_ut_lee);
//
//    g_vmcs_fields[0U] = 42U;
//    this->expect_true(get_vmcs_field(0U, name, exists) == 42U);
//}
//
//void
//intrinsics_ut::test_get_vmcs_field_if_exists()
//{
//    constexpr const auto name = "field";
//
//    auto exists = true;
//    auto verbose = true;
//    g_vmcs_fields[0U] = 42U;
//
//    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, !exists) == 0U);
//    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, exists) == 42U);
//}
//
//void
//intrinsics_ut::test_set_vmcs_field()
//{
//    constexpr const auto name("field");
//    auto exists = true;
//    g_vmcs_fields[0U] = 0U;
//
//    this->expect_exception([&] { set_vmcs_field(1U, 0U, name, !exists); }, ""_ut_lee);
//    this->expect_true(g_vmcs_fields[0U] == 0U);
//
//    this->expect_no_exception([&] { set_vmcs_field(1U, 0U, name, exists); });
//    this->expect_true(g_vmcs_fields[0U] == 1U);
//}
//
//void
//intrinsics_ut::test_set_vmcs_field_if_exists()
//{
//    constexpr const auto name("field");
//    auto exists = true;
//    auto verbose = true;
//    g_vmcs_fields[0U] = 42U;
//
//    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, !verbose, !exists); });
//    this->expect_true(g_vmcs_fields[0U] == 42U);
//
//    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, verbose, !exists); });
//    this->expect_true(g_vmcs_fields[0U] == 42U);
//
//    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, !verbose, exists); });
//    this->expect_true(g_vmcs_fields[0U] == 0U);
//
//    this->expect_no_exception([&] { set_vmcs_field_if_exists(1U, 0U, name, verbose, exists); });
//    this->expect_true(g_vmcs_fields[0U] == 1U);
//}
//
//void
//intrinsics_ut::test_set_vm_control()
//{
//    constexpr const auto name = "control";
//    auto exists = true;
//    auto mask = 0x0000000000000040UL;
//    auto ctls_addr = 0UL;
//    auto msr_addr = 0U;
//
//    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, !exists); },
//                           ""_ut_lee);
//
//    g_msrs[msr_addr] = ~mask;
//    this->expect_no_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); });
//    this->expect_true((g_vmcs_fields[ctls_addr] & mask) == 0UL);
//
//    g_msrs[msr_addr] = mask;
//    this->expect_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); },
//                           ""_ut_lee);
//
//    g_msrs[msr_addr] = mask << 32;
//    this->expect_no_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); });
//    this->expect_true((g_vmcs_fields[ctls_addr] & mask) != 0UL);
//
//    g_msrs[msr_addr] = ~(mask << 32);
//    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); },
//                           ""_ut_lee);
//}
//
//void
//intrinsics_ut::test_set_vm_control_if_allowed()
//{
//    constexpr const auto name = "control";
//    auto exists = true;
//    auto verbose = true;
//    auto mask = 0x0000000000000040UL;
//    auto ctls_addr = 0UL;
//    auto msr_addr = 0U;
//
//    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, !exists); });
//
//    g_vmcs_fields[ctls_addr] = mask;
//    g_msrs[msr_addr] = ~mask;
//
//    this->expect_no_exception([&] { set_vm_control_if_allowed(0UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
//    this->expect_true((g_vmcs_fields[ctls_addr] & mask) == 0UL);
//
//    g_msrs[msr_addr] = mask;
//    this->expect_no_exception([&] { set_vm_control_if_allowed(0UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
//
//    g_msrs[msr_addr] = mask << 32;
//    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
//    this->expect_true((g_vmcs_fields[ctls_addr] & mask) != 0UL);
//
//    g_msrs[msr_addr] = ~(mask << 32);
//    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
//}
//
//void
//intrinsics_ut::test_set_vm_function_control()
//{
//    constexpr const auto name = "control";
//    auto exists = true;
//    auto mask = 0x0000000000000040UL;
//    auto ctls_addr = 0UL;
//    auto msr_addr = 0U;
//
//    this->expect_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, !exists); },
//                           ""_ut_lee);
//    this->expect_no_exception([&] { set_vm_function_control(false, msr_addr, ctls_addr, name, mask, exists); });
//
//    g_msrs[msr_addr] = mask;
//    this->expect_no_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, exists); });
//
//    g_msrs[msr_addr] = ~mask;
//    this->expect_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, exists); },
//                           ""_ut_lee);
//}
//
//void
//intrinsics_ut::test_set_vm_function_control_if_allowed()
//{
//    constexpr const auto name = "control";
//    auto exists = true;
//    auto verbose = true;
//    auto mask = 0x0000000000000040UL;
//    auto ctls_addr = 0UL;
//    auto msr_addr = 0U;
//
//    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, !exists); });
//    this->expect_no_exception([&] { set_vm_function_control_if_allowed(false, msr_addr, ctls_addr, name, mask, verbose, exists); });
//
//    g_msrs[msr_addr] = mask;
//    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, exists); });
//
//    g_msrs[msr_addr] = ~mask;
//    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, exists); });
//}
//

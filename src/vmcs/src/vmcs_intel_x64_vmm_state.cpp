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

#include <vmcs/vmcs_intel_x64_vmm_state.h>

#include <memory_manager/pat_x64.h>
#include <memory_manager/root_page_table_x64.h>

using namespace x64;
using namespace intel_x64;

gdt_x64 g_gdt{7};
idt_x64 g_idt{256};

static auto gdt_setup = false;
static auto idt_setup = false;

vmcs_intel_x64_vmm_state::vmcs_intel_x64_vmm_state()
{
    if (!gdt_setup) {
        g_gdt.set_access_rights(1, access_rights::ring0_cs_descriptor);
        g_gdt.set_access_rights(2, access_rights::ring0_ss_descriptor);
        g_gdt.set_access_rights(3, access_rights::ring0_fs_descriptor);
        g_gdt.set_access_rights(4, access_rights::ring0_gs_descriptor);
        g_gdt.set_access_rights(5, access_rights::ring0_tr_descriptor);

        g_gdt.set_base(1, 0);
        g_gdt.set_base(2, 0);
        g_gdt.set_base(3, 0);
        g_gdt.set_base(4, 0);
        g_gdt.set_base(5, reinterpret_cast<gdt_x64::base_type>(&m_tss));

        g_gdt.set_limit(1, 0xFFFFFFFF);
        g_gdt.set_limit(2, 0xFFFFFFFF);
        g_gdt.set_limit(3, 0xFFFFFFFF);
        g_gdt.set_limit(4, 0xFFFFFFFF);
        g_gdt.set_limit(5, sizeof(m_tss));

        gdt_setup = true;
    }

    m_cs_index = 1;
    m_ss_index = 2;
    m_fs_index = 3;
    m_gs_index = 4;
    m_tr_index = 5;

    m_cs = gsl::narrow_cast<segment_register::value_type>(m_cs_index << 3);
    m_ss = gsl::narrow_cast<segment_register::value_type>(m_ss_index << 3);
    m_fs = gsl::narrow_cast<segment_register::value_type>(m_fs_index << 3);
    m_gs = gsl::narrow_cast<segment_register::value_type>(m_gs_index << 3);
    m_tr = gsl::narrow_cast<segment_register::value_type>(m_tr_index << 3);

    if (!idt_setup) {
















        // bffield(g_idt.base());





        g_idt.set_offset(0, reinterpret_cast<idt_x64::offset_type>(_isr0));
        g_idt.set_offset(1, reinterpret_cast<idt_x64::offset_type>(_isr1));
        g_idt.set_offset(2, reinterpret_cast<idt_x64::offset_type>(_isr2));
        g_idt.set_offset(3, reinterpret_cast<idt_x64::offset_type>(_isr3));
        g_idt.set_offset(4, reinterpret_cast<idt_x64::offset_type>(_isr4));
        g_idt.set_offset(5, reinterpret_cast<idt_x64::offset_type>(_isr5));
        g_idt.set_offset(6, reinterpret_cast<idt_x64::offset_type>(_isr6));
        g_idt.set_offset(7, reinterpret_cast<idt_x64::offset_type>(_isr7));
        g_idt.set_offset(8, reinterpret_cast<idt_x64::offset_type>(_isr8));
        g_idt.set_offset(9, reinterpret_cast<idt_x64::offset_type>(_isr9));
        g_idt.set_offset(10, reinterpret_cast<idt_x64::offset_type>(_isr10));
        g_idt.set_offset(11, reinterpret_cast<idt_x64::offset_type>(_isr11));
        g_idt.set_offset(12, reinterpret_cast<idt_x64::offset_type>(_isr12));
        g_idt.set_offset(13, reinterpret_cast<idt_x64::offset_type>(_isr13));
        g_idt.set_offset(14, reinterpret_cast<idt_x64::offset_type>(_isr14));
        g_idt.set_offset(15, reinterpret_cast<idt_x64::offset_type>(_isr15));
        g_idt.set_offset(16, reinterpret_cast<idt_x64::offset_type>(_isr16));
        g_idt.set_offset(17, reinterpret_cast<idt_x64::offset_type>(_isr17));
        g_idt.set_offset(18, reinterpret_cast<idt_x64::offset_type>(_isr18));
        g_idt.set_offset(19, reinterpret_cast<idt_x64::offset_type>(_isr19));
        g_idt.set_offset(20, reinterpret_cast<idt_x64::offset_type>(_isr20));
        g_idt.set_offset(21, reinterpret_cast<idt_x64::offset_type>(_isr21));
        g_idt.set_offset(22, reinterpret_cast<idt_x64::offset_type>(_isr22));
        g_idt.set_offset(23, reinterpret_cast<idt_x64::offset_type>(_isr23));
        g_idt.set_offset(24, reinterpret_cast<idt_x64::offset_type>(_isr24));
        g_idt.set_offset(25, reinterpret_cast<idt_x64::offset_type>(_isr25));
        g_idt.set_offset(26, reinterpret_cast<idt_x64::offset_type>(_isr26));
        g_idt.set_offset(27, reinterpret_cast<idt_x64::offset_type>(_isr27));
        g_idt.set_offset(28, reinterpret_cast<idt_x64::offset_type>(_isr28));
        g_idt.set_offset(29, reinterpret_cast<idt_x64::offset_type>(_isr29));
        g_idt.set_offset(30, reinterpret_cast<idt_x64::offset_type>(_isr30));
        g_idt.set_offset(31, reinterpret_cast<idt_x64::offset_type>(_isr31));
        g_idt.set_offset(32, reinterpret_cast<idt_x64::offset_type>(_isr32));
        g_idt.set_offset(33, reinterpret_cast<idt_x64::offset_type>(_isr33));
        g_idt.set_offset(34, reinterpret_cast<idt_x64::offset_type>(_isr34));
        g_idt.set_offset(35, reinterpret_cast<idt_x64::offset_type>(_isr35));
        g_idt.set_offset(36, reinterpret_cast<idt_x64::offset_type>(_isr36));
        g_idt.set_offset(37, reinterpret_cast<idt_x64::offset_type>(_isr37));
        g_idt.set_offset(38, reinterpret_cast<idt_x64::offset_type>(_isr38));
        g_idt.set_offset(39, reinterpret_cast<idt_x64::offset_type>(_isr39));
        g_idt.set_offset(40, reinterpret_cast<idt_x64::offset_type>(_isr40));
        g_idt.set_offset(41, reinterpret_cast<idt_x64::offset_type>(_isr41));
        g_idt.set_offset(42, reinterpret_cast<idt_x64::offset_type>(_isr42));
        g_idt.set_offset(43, reinterpret_cast<idt_x64::offset_type>(_isr43));
        g_idt.set_offset(44, reinterpret_cast<idt_x64::offset_type>(_isr44));
        g_idt.set_offset(45, reinterpret_cast<idt_x64::offset_type>(_isr45));
        g_idt.set_offset(46, reinterpret_cast<idt_x64::offset_type>(_isr46));
        g_idt.set_offset(47, reinterpret_cast<idt_x64::offset_type>(_isr47));
        g_idt.set_offset(48, reinterpret_cast<idt_x64::offset_type>(_isr48));
        g_idt.set_offset(49, reinterpret_cast<idt_x64::offset_type>(_isr49));
        g_idt.set_offset(50, reinterpret_cast<idt_x64::offset_type>(_isr50));
        g_idt.set_offset(51, reinterpret_cast<idt_x64::offset_type>(_isr51));
        g_idt.set_offset(52, reinterpret_cast<idt_x64::offset_type>(_isr52));
        g_idt.set_offset(53, reinterpret_cast<idt_x64::offset_type>(_isr53));
        g_idt.set_offset(54, reinterpret_cast<idt_x64::offset_type>(_isr54));
        g_idt.set_offset(55, reinterpret_cast<idt_x64::offset_type>(_isr55));
        g_idt.set_offset(56, reinterpret_cast<idt_x64::offset_type>(_isr56));
        g_idt.set_offset(57, reinterpret_cast<idt_x64::offset_type>(_isr57));
        g_idt.set_offset(58, reinterpret_cast<idt_x64::offset_type>(_isr58));
        g_idt.set_offset(59, reinterpret_cast<idt_x64::offset_type>(_isr59));
        g_idt.set_offset(60, reinterpret_cast<idt_x64::offset_type>(_isr60));
        g_idt.set_offset(61, reinterpret_cast<idt_x64::offset_type>(_isr61));
        g_idt.set_offset(62, reinterpret_cast<idt_x64::offset_type>(_isr62));
        g_idt.set_offset(63, reinterpret_cast<idt_x64::offset_type>(_isr63));
        g_idt.set_offset(64, reinterpret_cast<idt_x64::offset_type>(_isr64));
        g_idt.set_offset(65, reinterpret_cast<idt_x64::offset_type>(_isr65));
        g_idt.set_offset(66, reinterpret_cast<idt_x64::offset_type>(_isr66));
        g_idt.set_offset(67, reinterpret_cast<idt_x64::offset_type>(_isr67));
        g_idt.set_offset(68, reinterpret_cast<idt_x64::offset_type>(_isr68));
        g_idt.set_offset(69, reinterpret_cast<idt_x64::offset_type>(_isr69));
        g_idt.set_offset(70, reinterpret_cast<idt_x64::offset_type>(_isr70));
        g_idt.set_offset(71, reinterpret_cast<idt_x64::offset_type>(_isr71));
        g_idt.set_offset(72, reinterpret_cast<idt_x64::offset_type>(_isr72));
        g_idt.set_offset(73, reinterpret_cast<idt_x64::offset_type>(_isr73));
        g_idt.set_offset(74, reinterpret_cast<idt_x64::offset_type>(_isr74));
        g_idt.set_offset(75, reinterpret_cast<idt_x64::offset_type>(_isr75));
        g_idt.set_offset(76, reinterpret_cast<idt_x64::offset_type>(_isr76));
        g_idt.set_offset(77, reinterpret_cast<idt_x64::offset_type>(_isr77));
        g_idt.set_offset(78, reinterpret_cast<idt_x64::offset_type>(_isr78));
        g_idt.set_offset(79, reinterpret_cast<idt_x64::offset_type>(_isr79));
        g_idt.set_offset(80, reinterpret_cast<idt_x64::offset_type>(_isr80));
        g_idt.set_offset(81, reinterpret_cast<idt_x64::offset_type>(_isr81));
        g_idt.set_offset(82, reinterpret_cast<idt_x64::offset_type>(_isr82));
        g_idt.set_offset(83, reinterpret_cast<idt_x64::offset_type>(_isr83));
        g_idt.set_offset(84, reinterpret_cast<idt_x64::offset_type>(_isr84));
        g_idt.set_offset(85, reinterpret_cast<idt_x64::offset_type>(_isr85));
        g_idt.set_offset(86, reinterpret_cast<idt_x64::offset_type>(_isr86));
        g_idt.set_offset(87, reinterpret_cast<idt_x64::offset_type>(_isr87));
        g_idt.set_offset(88, reinterpret_cast<idt_x64::offset_type>(_isr88));
        g_idt.set_offset(89, reinterpret_cast<idt_x64::offset_type>(_isr89));
        g_idt.set_offset(90, reinterpret_cast<idt_x64::offset_type>(_isr90));
        g_idt.set_offset(91, reinterpret_cast<idt_x64::offset_type>(_isr91));
        g_idt.set_offset(92, reinterpret_cast<idt_x64::offset_type>(_isr92));
        g_idt.set_offset(93, reinterpret_cast<idt_x64::offset_type>(_isr93));
        g_idt.set_offset(94, reinterpret_cast<idt_x64::offset_type>(_isr94));
        g_idt.set_offset(95, reinterpret_cast<idt_x64::offset_type>(_isr95));
        g_idt.set_offset(96, reinterpret_cast<idt_x64::offset_type>(_isr96));
        g_idt.set_offset(97, reinterpret_cast<idt_x64::offset_type>(_isr97));
        g_idt.set_offset(98, reinterpret_cast<idt_x64::offset_type>(_isr98));
        g_idt.set_offset(99, reinterpret_cast<idt_x64::offset_type>(_isr99));
        g_idt.set_offset(100, reinterpret_cast<idt_x64::offset_type>(_isr100));
        g_idt.set_offset(101, reinterpret_cast<idt_x64::offset_type>(_isr101));
        g_idt.set_offset(102, reinterpret_cast<idt_x64::offset_type>(_isr102));
        g_idt.set_offset(103, reinterpret_cast<idt_x64::offset_type>(_isr103));
        g_idt.set_offset(104, reinterpret_cast<idt_x64::offset_type>(_isr104));
        g_idt.set_offset(105, reinterpret_cast<idt_x64::offset_type>(_isr105));
        g_idt.set_offset(106, reinterpret_cast<idt_x64::offset_type>(_isr106));
        g_idt.set_offset(107, reinterpret_cast<idt_x64::offset_type>(_isr107));
        g_idt.set_offset(108, reinterpret_cast<idt_x64::offset_type>(_isr108));
        g_idt.set_offset(109, reinterpret_cast<idt_x64::offset_type>(_isr109));
        g_idt.set_offset(110, reinterpret_cast<idt_x64::offset_type>(_isr110));
        g_idt.set_offset(111, reinterpret_cast<idt_x64::offset_type>(_isr111));
        g_idt.set_offset(112, reinterpret_cast<idt_x64::offset_type>(_isr112));
        g_idt.set_offset(113, reinterpret_cast<idt_x64::offset_type>(_isr113));
        g_idt.set_offset(114, reinterpret_cast<idt_x64::offset_type>(_isr114));
        g_idt.set_offset(115, reinterpret_cast<idt_x64::offset_type>(_isr115));
        g_idt.set_offset(116, reinterpret_cast<idt_x64::offset_type>(_isr116));
        g_idt.set_offset(117, reinterpret_cast<idt_x64::offset_type>(_isr117));
        g_idt.set_offset(118, reinterpret_cast<idt_x64::offset_type>(_isr118));
        g_idt.set_offset(119, reinterpret_cast<idt_x64::offset_type>(_isr119));
        g_idt.set_offset(120, reinterpret_cast<idt_x64::offset_type>(_isr120));
        g_idt.set_offset(121, reinterpret_cast<idt_x64::offset_type>(_isr121));
        g_idt.set_offset(122, reinterpret_cast<idt_x64::offset_type>(_isr122));
        g_idt.set_offset(123, reinterpret_cast<idt_x64::offset_type>(_isr123));
        g_idt.set_offset(124, reinterpret_cast<idt_x64::offset_type>(_isr124));
        g_idt.set_offset(125, reinterpret_cast<idt_x64::offset_type>(_isr125));
        g_idt.set_offset(126, reinterpret_cast<idt_x64::offset_type>(_isr126));
        g_idt.set_offset(127, reinterpret_cast<idt_x64::offset_type>(_isr127));
        g_idt.set_offset(128, reinterpret_cast<idt_x64::offset_type>(_isr128));
        g_idt.set_offset(129, reinterpret_cast<idt_x64::offset_type>(_isr129));
        g_idt.set_offset(130, reinterpret_cast<idt_x64::offset_type>(_isr130));
        g_idt.set_offset(131, reinterpret_cast<idt_x64::offset_type>(_isr131));
        g_idt.set_offset(132, reinterpret_cast<idt_x64::offset_type>(_isr132));
        g_idt.set_offset(133, reinterpret_cast<idt_x64::offset_type>(_isr133));
        g_idt.set_offset(134, reinterpret_cast<idt_x64::offset_type>(_isr134));
        g_idt.set_offset(135, reinterpret_cast<idt_x64::offset_type>(_isr135));
        g_idt.set_offset(136, reinterpret_cast<idt_x64::offset_type>(_isr136));
        g_idt.set_offset(137, reinterpret_cast<idt_x64::offset_type>(_isr137));
        g_idt.set_offset(138, reinterpret_cast<idt_x64::offset_type>(_isr138));
        g_idt.set_offset(139, reinterpret_cast<idt_x64::offset_type>(_isr139));
        g_idt.set_offset(140, reinterpret_cast<idt_x64::offset_type>(_isr140));
        g_idt.set_offset(141, reinterpret_cast<idt_x64::offset_type>(_isr141));
        g_idt.set_offset(142, reinterpret_cast<idt_x64::offset_type>(_isr142));
        g_idt.set_offset(143, reinterpret_cast<idt_x64::offset_type>(_isr143));
        g_idt.set_offset(144, reinterpret_cast<idt_x64::offset_type>(_isr144));
        g_idt.set_offset(145, reinterpret_cast<idt_x64::offset_type>(_isr145));
        g_idt.set_offset(146, reinterpret_cast<idt_x64::offset_type>(_isr146));
        g_idt.set_offset(147, reinterpret_cast<idt_x64::offset_type>(_isr147));
        g_idt.set_offset(148, reinterpret_cast<idt_x64::offset_type>(_isr148));
        g_idt.set_offset(149, reinterpret_cast<idt_x64::offset_type>(_isr149));
        g_idt.set_offset(150, reinterpret_cast<idt_x64::offset_type>(_isr150));
        g_idt.set_offset(151, reinterpret_cast<idt_x64::offset_type>(_isr151));
        g_idt.set_offset(152, reinterpret_cast<idt_x64::offset_type>(_isr152));
        g_idt.set_offset(153, reinterpret_cast<idt_x64::offset_type>(_isr153));
        g_idt.set_offset(154, reinterpret_cast<idt_x64::offset_type>(_isr154));
        g_idt.set_offset(155, reinterpret_cast<idt_x64::offset_type>(_isr155));
        g_idt.set_offset(156, reinterpret_cast<idt_x64::offset_type>(_isr156));
        g_idt.set_offset(157, reinterpret_cast<idt_x64::offset_type>(_isr157));
        g_idt.set_offset(158, reinterpret_cast<idt_x64::offset_type>(_isr158));
        g_idt.set_offset(159, reinterpret_cast<idt_x64::offset_type>(_isr159));
        g_idt.set_offset(160, reinterpret_cast<idt_x64::offset_type>(_isr160));
        g_idt.set_offset(161, reinterpret_cast<idt_x64::offset_type>(_isr161));
        g_idt.set_offset(162, reinterpret_cast<idt_x64::offset_type>(_isr162));
        g_idt.set_offset(163, reinterpret_cast<idt_x64::offset_type>(_isr163));
        g_idt.set_offset(164, reinterpret_cast<idt_x64::offset_type>(_isr164));
        g_idt.set_offset(165, reinterpret_cast<idt_x64::offset_type>(_isr165));
        g_idt.set_offset(166, reinterpret_cast<idt_x64::offset_type>(_isr166));
        g_idt.set_offset(167, reinterpret_cast<idt_x64::offset_type>(_isr167));
        g_idt.set_offset(168, reinterpret_cast<idt_x64::offset_type>(_isr168));
        g_idt.set_offset(169, reinterpret_cast<idt_x64::offset_type>(_isr169));
        g_idt.set_offset(170, reinterpret_cast<idt_x64::offset_type>(_isr170));
        g_idt.set_offset(171, reinterpret_cast<idt_x64::offset_type>(_isr171));
        g_idt.set_offset(172, reinterpret_cast<idt_x64::offset_type>(_isr172));
        g_idt.set_offset(173, reinterpret_cast<idt_x64::offset_type>(_isr173));
        g_idt.set_offset(174, reinterpret_cast<idt_x64::offset_type>(_isr174));
        g_idt.set_offset(175, reinterpret_cast<idt_x64::offset_type>(_isr175));
        g_idt.set_offset(176, reinterpret_cast<idt_x64::offset_type>(_isr176));
        g_idt.set_offset(177, reinterpret_cast<idt_x64::offset_type>(_isr177));
        g_idt.set_offset(178, reinterpret_cast<idt_x64::offset_type>(_isr178));
        g_idt.set_offset(179, reinterpret_cast<idt_x64::offset_type>(_isr179));
        g_idt.set_offset(180, reinterpret_cast<idt_x64::offset_type>(_isr180));
        g_idt.set_offset(181, reinterpret_cast<idt_x64::offset_type>(_isr181));
        g_idt.set_offset(182, reinterpret_cast<idt_x64::offset_type>(_isr182));
        g_idt.set_offset(183, reinterpret_cast<idt_x64::offset_type>(_isr183));
        g_idt.set_offset(184, reinterpret_cast<idt_x64::offset_type>(_isr184));
        g_idt.set_offset(185, reinterpret_cast<idt_x64::offset_type>(_isr185));
        g_idt.set_offset(186, reinterpret_cast<idt_x64::offset_type>(_isr186));
        g_idt.set_offset(187, reinterpret_cast<idt_x64::offset_type>(_isr187));
        g_idt.set_offset(188, reinterpret_cast<idt_x64::offset_type>(_isr188));
        g_idt.set_offset(189, reinterpret_cast<idt_x64::offset_type>(_isr189));
        g_idt.set_offset(190, reinterpret_cast<idt_x64::offset_type>(_isr190));
        g_idt.set_offset(191, reinterpret_cast<idt_x64::offset_type>(_isr191));
        g_idt.set_offset(192, reinterpret_cast<idt_x64::offset_type>(_isr192));
        g_idt.set_offset(193, reinterpret_cast<idt_x64::offset_type>(_isr193));
        g_idt.set_offset(194, reinterpret_cast<idt_x64::offset_type>(_isr194));
        g_idt.set_offset(195, reinterpret_cast<idt_x64::offset_type>(_isr195));
        g_idt.set_offset(196, reinterpret_cast<idt_x64::offset_type>(_isr196));
        g_idt.set_offset(197, reinterpret_cast<idt_x64::offset_type>(_isr197));
        g_idt.set_offset(198, reinterpret_cast<idt_x64::offset_type>(_isr198));
        g_idt.set_offset(199, reinterpret_cast<idt_x64::offset_type>(_isr199));
        g_idt.set_offset(200, reinterpret_cast<idt_x64::offset_type>(_isr200));
        g_idt.set_offset(201, reinterpret_cast<idt_x64::offset_type>(_isr201));
        g_idt.set_offset(202, reinterpret_cast<idt_x64::offset_type>(_isr202));
        g_idt.set_offset(203, reinterpret_cast<idt_x64::offset_type>(_isr203));
        g_idt.set_offset(204, reinterpret_cast<idt_x64::offset_type>(_isr204));
        g_idt.set_offset(205, reinterpret_cast<idt_x64::offset_type>(_isr205));
        g_idt.set_offset(206, reinterpret_cast<idt_x64::offset_type>(_isr206));
        g_idt.set_offset(207, reinterpret_cast<idt_x64::offset_type>(_isr207));
        g_idt.set_offset(208, reinterpret_cast<idt_x64::offset_type>(_isr208));
        g_idt.set_offset(209, reinterpret_cast<idt_x64::offset_type>(_isr209));
        g_idt.set_offset(210, reinterpret_cast<idt_x64::offset_type>(_isr210));
        g_idt.set_offset(211, reinterpret_cast<idt_x64::offset_type>(_isr211));
        g_idt.set_offset(212, reinterpret_cast<idt_x64::offset_type>(_isr212));
        g_idt.set_offset(213, reinterpret_cast<idt_x64::offset_type>(_isr213));
        g_idt.set_offset(214, reinterpret_cast<idt_x64::offset_type>(_isr214));
        g_idt.set_offset(215, reinterpret_cast<idt_x64::offset_type>(_isr215));
        g_idt.set_offset(216, reinterpret_cast<idt_x64::offset_type>(_isr216));
        g_idt.set_offset(217, reinterpret_cast<idt_x64::offset_type>(_isr217));
        g_idt.set_offset(218, reinterpret_cast<idt_x64::offset_type>(_isr218));
        g_idt.set_offset(219, reinterpret_cast<idt_x64::offset_type>(_isr219));
        g_idt.set_offset(220, reinterpret_cast<idt_x64::offset_type>(_isr220));
        g_idt.set_offset(221, reinterpret_cast<idt_x64::offset_type>(_isr221));
        g_idt.set_offset(222, reinterpret_cast<idt_x64::offset_type>(_isr222));
        g_idt.set_offset(223, reinterpret_cast<idt_x64::offset_type>(_isr223));
        g_idt.set_offset(224, reinterpret_cast<idt_x64::offset_type>(_isr224));
        g_idt.set_offset(225, reinterpret_cast<idt_x64::offset_type>(_isr225));
        g_idt.set_offset(226, reinterpret_cast<idt_x64::offset_type>(_isr226));
        g_idt.set_offset(227, reinterpret_cast<idt_x64::offset_type>(_isr227));
        g_idt.set_offset(228, reinterpret_cast<idt_x64::offset_type>(_isr228));
        g_idt.set_offset(229, reinterpret_cast<idt_x64::offset_type>(_isr229));
        g_idt.set_offset(230, reinterpret_cast<idt_x64::offset_type>(_isr230));
        g_idt.set_offset(231, reinterpret_cast<idt_x64::offset_type>(_isr231));
        g_idt.set_offset(232, reinterpret_cast<idt_x64::offset_type>(_isr232));
        g_idt.set_offset(233, reinterpret_cast<idt_x64::offset_type>(_isr233));
        g_idt.set_offset(234, reinterpret_cast<idt_x64::offset_type>(_isr234));
        g_idt.set_offset(235, reinterpret_cast<idt_x64::offset_type>(_isr235));
        g_idt.set_offset(236, reinterpret_cast<idt_x64::offset_type>(_isr236));
        g_idt.set_offset(237, reinterpret_cast<idt_x64::offset_type>(_isr237));
        g_idt.set_offset(238, reinterpret_cast<idt_x64::offset_type>(_isr238));
        g_idt.set_offset(239, reinterpret_cast<idt_x64::offset_type>(_isr239));
        g_idt.set_offset(240, reinterpret_cast<idt_x64::offset_type>(_isr240));
        g_idt.set_offset(241, reinterpret_cast<idt_x64::offset_type>(_isr241));
        g_idt.set_offset(242, reinterpret_cast<idt_x64::offset_type>(_isr242));
        g_idt.set_offset(243, reinterpret_cast<idt_x64::offset_type>(_isr243));
        g_idt.set_offset(244, reinterpret_cast<idt_x64::offset_type>(_isr244));
        g_idt.set_offset(245, reinterpret_cast<idt_x64::offset_type>(_isr245));
        g_idt.set_offset(246, reinterpret_cast<idt_x64::offset_type>(_isr246));
        g_idt.set_offset(247, reinterpret_cast<idt_x64::offset_type>(_isr247));
        g_idt.set_offset(248, reinterpret_cast<idt_x64::offset_type>(_isr248));
        g_idt.set_offset(249, reinterpret_cast<idt_x64::offset_type>(_isr249));
        g_idt.set_offset(250, reinterpret_cast<idt_x64::offset_type>(_isr250));
        g_idt.set_offset(251, reinterpret_cast<idt_x64::offset_type>(_isr251));
        g_idt.set_offset(252, reinterpret_cast<idt_x64::offset_type>(_isr252));
        g_idt.set_offset(253, reinterpret_cast<idt_x64::offset_type>(_isr253));
        g_idt.set_offset(254, reinterpret_cast<idt_x64::offset_type>(_isr254));
        g_idt.set_offset(255, reinterpret_cast<idt_x64::offset_type>(_isr255));

        for (auto i = 0U; i < 256; i++) {
            g_idt.set_selector(i, 0x8);
            g_idt.set_present(i, true);
        }

        idt_setup = true;
    }

    m_cr0 = 0;
    m_cr0 |= cr0::protection_enable::mask;
    m_cr0 |= cr0::monitor_coprocessor::mask;
    m_cr0 |= cr0::extension_type::mask;
    m_cr0 |= cr0::numeric_error::mask;
    m_cr0 |= cr0::write_protect::mask;
    m_cr0 |= cr0::paging::mask;

    m_cr3 = g_pt->cr3();

    m_cr4 = 0;
    m_cr4 |= cr4::v8086_mode_extensions::mask;
    m_cr4 |= cr4::protected_mode_virtual_interrupts::mask;
    m_cr4 |= cr4::time_stamp_disable::mask;
    m_cr4 |= cr4::debugging_extensions::mask;
    m_cr4 |= cr4::page_size_extensions::mask;
    m_cr4 |= cr4::physical_address_extensions::mask;
    m_cr4 |= cr4::machine_check_enable::mask;
    m_cr4 |= cr4::page_global_enable::mask;
    m_cr4 |= cr4::performance_monitor_counter_enable::mask;
    m_cr4 |= cr4::osfxsr::mask;
    m_cr4 |= cr4::osxmmexcpt::mask;
    m_cr4 |= cr4::vmx_enable_bit::mask;

    if (intel_x64::cpuid::feature_information::ecx::xsave::is_enabled()) {
        m_cr4 |= cr4::osxsave::mask;
    }

    if (intel_x64::cpuid::extended_feature_flags::subleaf0::ebx::smep::is_enabled()) {
        m_cr4 |= cr4::smep_enable_bit::mask;
    }

    if (intel_x64::cpuid::extended_feature_flags::subleaf0::ebx::smap::is_enabled()) {
        m_cr4 |= cr4::smap_enable_bit::mask;
    }

    m_rflags = 0;

    m_ia32_pat_msr = x64::pat::pat_value;

    m_ia32_efer_msr = 0;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lme::mask;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::lma::mask;
    m_ia32_efer_msr |= intel_x64::msrs::ia32_efer::nxe::mask;

    m_ist1 = std::make_unique<gsl::byte[]>(STACK_SIZE);
    m_tss.ist1 = reinterpret_cast<uint64_t>(m_ist1.get()) + STACK_SIZE - 0x10;
}

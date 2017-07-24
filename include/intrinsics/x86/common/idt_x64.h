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

#ifndef IDT_X64_H
#define IDT_X64_H

#include <vector>
#include <algorithm>

#include <bfgsl.h>
#include <bfexception.h>
#include <bftypes.h>

#include <intrinsics/x86/common/x64.h>

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
// Interrupt Descriptor Table Register
// -----------------------------------------------------------------------------

#pragma pack(push, 1)

struct EXPORT_INTRINSICS idt_reg_x64_t {
    using limit_type = uint16_t;
    using base_type = uint64_t *;

    limit_type limit{0};
    base_type base{nullptr};

    idt_reg_x64_t() noexcept = default;

    idt_reg_x64_t(base_type b, limit_type l) noexcept :
        limit(l),
        base(b)
    { }
};

#pragma pack(pop)

// -----------------------------------------------------------------------------
// Intrinsics
// -----------------------------------------------------------------------------

extern "C" EXPORT_INTRINSICS void _read_idt(idt_reg_x64_t *idt_reg) noexcept;
extern "C" EXPORT_INTRINSICS void _write_idt(idt_reg_x64_t *idt_reg) noexcept;

// -----------------------------------------------------------------------------
// IDT Functions
// -----------------------------------------------------------------------------

// *INDENT-OFF*

namespace x64
{
namespace idt
{
    inline auto get() noexcept
    {
        auto reg = idt_reg_x64_t{};
        _read_idt(&reg);

        return reg;
    }

    inline void set(idt_reg_x64_t::base_type base, idt_reg_x64_t::limit_type limit) noexcept
    {
        auto reg = idt_reg_x64_t{base, limit};
        _write_idt(&reg);
    }

    namespace base
    {
        inline auto get() noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            return reg.base;
        }

        inline void set(idt_reg_x64_t::base_type base) noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            reg.base = base;
            _write_idt(&reg);
        }
    }

    namespace limit
    {
        inline auto get() noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            return reg.limit;
        }

        inline void set(idt_reg_x64_t::limit_type limit) noexcept
        {
            auto reg = idt_reg_x64_t{};
            _read_idt(&reg);

            reg.limit = limit;
            _write_idt(&reg);
        }
    }
}
}
// *INDENT-ON*

// -----------------------------------------------------------------------------
// Interrupt Descriptor Table
// -----------------------------------------------------------------------------

/// Interrupt Descriptor Table
///
///
class EXPORT_INTRINSICS idt_x64
{
public:

    using size_type = uint16_t;
    using index_type = uint32_t;
    using integer_pointer = uintptr_t;
    using interrupt_descriptor_type = uint64_t;
    using offset_type = uint64_t;
    using selector_type = uint32_t;

    /// Constructor
    ///
    /// Wraps around the IDT that is currently stored in the hardware.
    ///
    /// @expects none
    /// @ensures none
    ///
    idt_x64() noexcept
    {
        guard_exceptions([&] {
            m_idt_reg.base = x64::idt::base::get();
            m_idt_reg.limit = x64::idt::limit::get();

            std::copy_n(m_idt_reg.base, (m_idt_reg.limit >> 3) + 1, std::back_inserter(m_idt));
        });
    }

    /// Constructor
    ///
    /// Creates a new IDT, with size defining the number of descriptors
    /// in the IDT.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param size number of entries in the IDT
    ///
    idt_x64(size_type size) noexcept :
        m_idt(size * 2U)
    {
        guard_exceptions([&] {
            m_idt_reg.base = m_idt.data();
            m_idt_reg.limit = gsl::narrow_cast<size_type>((size << 4) - 1);
        });
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~idt_x64() = default;

    /// IDT Base Address
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the base address of the IDT itself.
    ///
    auto base() const
    { return reinterpret_cast<integer_pointer>(m_idt_reg.base); }

    /// IDT Limit
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return returns the size of the IDT itself in bytes
    ///
    auto limit() const
    { return m_idt_reg.limit; }

    /// Set Descriptor Offset
    ///
    /// @expects index < m_idt.size() + 1
    /// @expects offset is canonical
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param offset the RIP address of the ISR. For code/data descriptor this needs to
    ///     be 0, and for a TSS this is a 64bit virtual address.
    ///
    void set_offset(index_type index, offset_type offset)
    {
        expects(x64::is_address_canonical(offset));

        auto sd1 = m_idt.at((index * 2U) + 0U) & 0x0000FFFFFFFF0000;
        auto sd2 = m_idt.at((index * 2U) + 1U) & 0xFFFFFFFF00000000;

        // The segment base description can be found in the Intel's software
        // developer's manual, volume 3, chapter 6.14.1
        //
        // Note that in 64bit mode, interrupt descriptors are 16 bytes long
        // instead of the traditional 8 bytes.
        //
        // ------------------------------------------------------------------
        // |                      Offset 63-32                              |
        // ------------------------------------------------------------------
        // |         Offset 31-16        |                                  |
        // ------------------------------------------------------------------
        // |                             |           Offset 15-00           |
        // ------------------------------------------------------------------
        //

        auto offset_15_00 = ((offset & 0x000000000000FFFF) << 0);
        auto offset_31_16 = ((offset & 0x00000000FFFF0000) << 32);
        auto offset_63_32 = ((offset & 0xFFFFFFFF00000000) >> 32);

        m_idt.at((index * 2U) + 0U) = sd1 | offset_31_16 | offset_15_00;
        m_idt.at((index * 2U) + 1U) = sd2 | offset_63_32;
    }

    /// Get Descriptor Offset
    ///
    /// @expects index < m_idt.size() + 1
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the offset
    ///
    offset_type offset(index_type index) const
    {
        auto sd1 = m_idt.at((index * 2U) + 0U);
        auto sd2 = m_idt.at((index * 2U) + 1U);

        // ------------------------------------------------------------------
        // |                      Offset 63-32                              |
        // ------------------------------------------------------------------
        // |         Offset 31-16        |                                  |
        // ------------------------------------------------------------------
        // |                             |           Offset 15-00           |
        // ------------------------------------------------------------------

        auto base_15_00 = ((sd1 & 0x000000000000FFFF) >> 0);
        auto base_31_16 = ((sd1 & 0xFFFF000000000000) >> 32);
        auto base_63_32 = ((sd2 & 0x00000000FFFFFFFF) << 32);

        return base_63_32 | base_31_16 | base_15_00;
    }

    /// Set Descriptor Segment Selector
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param selector the descriptor
    ///
    void set_selector(index_type index, selector_type selector)
    {
        auto sd1 = m_idt.at(index * 2U) & 0xFFFFFFFF0000FFFF;

        // ------------------------------------------------------------------
        // |                                                                |
        // ------------------------------------------------------------------
        // |         Selector 31-16         |                               |
        // ------------------------------------------------------------------

        m_idt.at(index * 2U) = sd1 | ((selector & 0x000000000000FFFF) << 16);
    }

    /// Get Descriptor Segment Selector
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the selector
    ///
    selector_type selector(index_type index) const
    {
        auto sd1 = m_idt.at(index * 2U);

        // ------------------------------------------------------------------
        // |                                                                |
        // ------------------------------------------------------------------
        // |         Selector 31-16         |                               |
        // ------------------------------------------------------------------

        return ((sd1 & 0x00000000FFFF0000) >> 16);
    }

    /// Set Present
    ///
    /// Sets the present bit. Since the IDT is only used by the hypervisor,
    /// this also sets DPL = 0 and type = interrupt gate when enabling the
    /// descriptor
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @param p true if present, false otherwise
    ///
    void set_present(index_type index, bool selector)
    {
        auto sd1 = m_idt.at(index * 2U) & 0xFFFF0000FFFFFFFF;

        // ------------------------------------------------------------------
        // |                                |P|                             |
        // ------------------------------------------------------------------
        // |                                |                               |
        // ------------------------------------------------------------------

        m_idt.at(index * 2U) = selector ? sd1 | 0x00008E0100000000 : sd1;
    }

    /// Get Present
    ///
    /// @expects index < m_idt.size()
    /// @ensures none
    ///
    /// @param index the index of the IDT descriptor
    /// @return the selector
    ///
    bool present(index_type index) const
    {
        // ------------------------------------------------------------------
        // |                                                                |
        // ------------------------------------------------------------------
        // |         Selector 31-16         |                               |
        // ------------------------------------------------------------------

        return m_idt.at(index * 2U) & 0x0000800000000000;
    }

    //PRIVATE

    idt_reg_x64_t m_idt_reg;
    std::vector<interrupt_descriptor_type> m_idt;

public:

    idt_x64(idt_x64 &&) noexcept = delete;
    idt_x64 &operator=(idt_x64 &&) noexcept = delete;

    idt_x64(const idt_x64 &) = delete;
    idt_x64 &operator=(const idt_x64 &) = delete;
};

extern "C" void _isr0(void) noexcept;
extern "C" void _isr1(void) noexcept;
extern "C" void _isr2(void) noexcept;
extern "C" void _isr3(void) noexcept;
extern "C" void _isr4(void) noexcept;
extern "C" void _isr5(void) noexcept;
extern "C" void _isr6(void) noexcept;
extern "C" void _isr7(void) noexcept;
extern "C" void _isr8(void) noexcept;
extern "C" void _isr9(void) noexcept;
extern "C" void _isr10(void) noexcept;
extern "C" void _isr11(void) noexcept;
extern "C" void _isr12(void) noexcept;
extern "C" void _isr13(void) noexcept;
extern "C" void _isr14(void) noexcept;
extern "C" void _isr15(void) noexcept;
extern "C" void _isr16(void) noexcept;
extern "C" void _isr17(void) noexcept;
extern "C" void _isr18(void) noexcept;
extern "C" void _isr19(void) noexcept;
extern "C" void _isr20(void) noexcept;
extern "C" void _isr21(void) noexcept;
extern "C" void _isr22(void) noexcept;
extern "C" void _isr23(void) noexcept;
extern "C" void _isr24(void) noexcept;
extern "C" void _isr25(void) noexcept;
extern "C" void _isr26(void) noexcept;
extern "C" void _isr27(void) noexcept;
extern "C" void _isr28(void) noexcept;
extern "C" void _isr29(void) noexcept;
extern "C" void _isr30(void) noexcept;
extern "C" void _isr31(void) noexcept;
extern "C" void _isr32(void) noexcept;
extern "C" void _isr33(void) noexcept;
extern "C" void _isr34(void) noexcept;
extern "C" void _isr35(void) noexcept;
extern "C" void _isr36(void) noexcept;
extern "C" void _isr37(void) noexcept;
extern "C" void _isr38(void) noexcept;
extern "C" void _isr39(void) noexcept;
extern "C" void _isr40(void) noexcept;
extern "C" void _isr41(void) noexcept;
extern "C" void _isr42(void) noexcept;
extern "C" void _isr43(void) noexcept;
extern "C" void _isr44(void) noexcept;
extern "C" void _isr45(void) noexcept;
extern "C" void _isr46(void) noexcept;
extern "C" void _isr47(void) noexcept;
extern "C" void _isr48(void) noexcept;
extern "C" void _isr49(void) noexcept;
extern "C" void _isr50(void) noexcept;
extern "C" void _isr51(void) noexcept;
extern "C" void _isr52(void) noexcept;
extern "C" void _isr53(void) noexcept;
extern "C" void _isr54(void) noexcept;
extern "C" void _isr55(void) noexcept;
extern "C" void _isr56(void) noexcept;
extern "C" void _isr57(void) noexcept;
extern "C" void _isr58(void) noexcept;
extern "C" void _isr59(void) noexcept;
extern "C" void _isr60(void) noexcept;
extern "C" void _isr61(void) noexcept;
extern "C" void _isr62(void) noexcept;
extern "C" void _isr63(void) noexcept;
extern "C" void _isr64(void) noexcept;
extern "C" void _isr65(void) noexcept;
extern "C" void _isr66(void) noexcept;
extern "C" void _isr67(void) noexcept;
extern "C" void _isr68(void) noexcept;
extern "C" void _isr69(void) noexcept;
extern "C" void _isr70(void) noexcept;
extern "C" void _isr71(void) noexcept;
extern "C" void _isr72(void) noexcept;
extern "C" void _isr73(void) noexcept;
extern "C" void _isr74(void) noexcept;
extern "C" void _isr75(void) noexcept;
extern "C" void _isr76(void) noexcept;
extern "C" void _isr77(void) noexcept;
extern "C" void _isr78(void) noexcept;
extern "C" void _isr79(void) noexcept;
extern "C" void _isr80(void) noexcept;
extern "C" void _isr81(void) noexcept;
extern "C" void _isr82(void) noexcept;
extern "C" void _isr83(void) noexcept;
extern "C" void _isr84(void) noexcept;
extern "C" void _isr85(void) noexcept;
extern "C" void _isr86(void) noexcept;
extern "C" void _isr87(void) noexcept;
extern "C" void _isr88(void) noexcept;
extern "C" void _isr89(void) noexcept;
extern "C" void _isr90(void) noexcept;
extern "C" void _isr91(void) noexcept;
extern "C" void _isr92(void) noexcept;
extern "C" void _isr93(void) noexcept;
extern "C" void _isr94(void) noexcept;
extern "C" void _isr95(void) noexcept;
extern "C" void _isr96(void) noexcept;
extern "C" void _isr97(void) noexcept;
extern "C" void _isr98(void) noexcept;
extern "C" void _isr99(void) noexcept;
extern "C" void _isr100(void) noexcept;
extern "C" void _isr101(void) noexcept;
extern "C" void _isr102(void) noexcept;
extern "C" void _isr103(void) noexcept;
extern "C" void _isr104(void) noexcept;
extern "C" void _isr105(void) noexcept;
extern "C" void _isr106(void) noexcept;
extern "C" void _isr107(void) noexcept;
extern "C" void _isr108(void) noexcept;
extern "C" void _isr109(void) noexcept;
extern "C" void _isr110(void) noexcept;
extern "C" void _isr111(void) noexcept;
extern "C" void _isr112(void) noexcept;
extern "C" void _isr113(void) noexcept;
extern "C" void _isr114(void) noexcept;
extern "C" void _isr115(void) noexcept;
extern "C" void _isr116(void) noexcept;
extern "C" void _isr117(void) noexcept;
extern "C" void _isr118(void) noexcept;
extern "C" void _isr119(void) noexcept;
extern "C" void _isr120(void) noexcept;
extern "C" void _isr121(void) noexcept;
extern "C" void _isr122(void) noexcept;
extern "C" void _isr123(void) noexcept;
extern "C" void _isr124(void) noexcept;
extern "C" void _isr125(void) noexcept;
extern "C" void _isr126(void) noexcept;
extern "C" void _isr127(void) noexcept;
extern "C" void _isr128(void) noexcept;
extern "C" void _isr129(void) noexcept;
extern "C" void _isr130(void) noexcept;
extern "C" void _isr131(void) noexcept;
extern "C" void _isr132(void) noexcept;
extern "C" void _isr133(void) noexcept;
extern "C" void _isr134(void) noexcept;
extern "C" void _isr135(void) noexcept;
extern "C" void _isr136(void) noexcept;
extern "C" void _isr137(void) noexcept;
extern "C" void _isr138(void) noexcept;
extern "C" void _isr139(void) noexcept;
extern "C" void _isr140(void) noexcept;
extern "C" void _isr141(void) noexcept;
extern "C" void _isr142(void) noexcept;
extern "C" void _isr143(void) noexcept;
extern "C" void _isr144(void) noexcept;
extern "C" void _isr145(void) noexcept;
extern "C" void _isr146(void) noexcept;
extern "C" void _isr147(void) noexcept;
extern "C" void _isr148(void) noexcept;
extern "C" void _isr149(void) noexcept;
extern "C" void _isr150(void) noexcept;
extern "C" void _isr151(void) noexcept;
extern "C" void _isr152(void) noexcept;
extern "C" void _isr153(void) noexcept;
extern "C" void _isr154(void) noexcept;
extern "C" void _isr155(void) noexcept;
extern "C" void _isr156(void) noexcept;
extern "C" void _isr157(void) noexcept;
extern "C" void _isr158(void) noexcept;
extern "C" void _isr159(void) noexcept;
extern "C" void _isr160(void) noexcept;
extern "C" void _isr161(void) noexcept;
extern "C" void _isr162(void) noexcept;
extern "C" void _isr163(void) noexcept;
extern "C" void _isr164(void) noexcept;
extern "C" void _isr165(void) noexcept;
extern "C" void _isr166(void) noexcept;
extern "C" void _isr167(void) noexcept;
extern "C" void _isr168(void) noexcept;
extern "C" void _isr169(void) noexcept;
extern "C" void _isr170(void) noexcept;
extern "C" void _isr171(void) noexcept;
extern "C" void _isr172(void) noexcept;
extern "C" void _isr173(void) noexcept;
extern "C" void _isr174(void) noexcept;
extern "C" void _isr175(void) noexcept;
extern "C" void _isr176(void) noexcept;
extern "C" void _isr177(void) noexcept;
extern "C" void _isr178(void) noexcept;
extern "C" void _isr179(void) noexcept;
extern "C" void _isr180(void) noexcept;
extern "C" void _isr181(void) noexcept;
extern "C" void _isr182(void) noexcept;
extern "C" void _isr183(void) noexcept;
extern "C" void _isr184(void) noexcept;
extern "C" void _isr185(void) noexcept;
extern "C" void _isr186(void) noexcept;
extern "C" void _isr187(void) noexcept;
extern "C" void _isr188(void) noexcept;
extern "C" void _isr189(void) noexcept;
extern "C" void _isr190(void) noexcept;
extern "C" void _isr191(void) noexcept;
extern "C" void _isr192(void) noexcept;
extern "C" void _isr193(void) noexcept;
extern "C" void _isr194(void) noexcept;
extern "C" void _isr195(void) noexcept;
extern "C" void _isr196(void) noexcept;
extern "C" void _isr197(void) noexcept;
extern "C" void _isr198(void) noexcept;
extern "C" void _isr199(void) noexcept;
extern "C" void _isr200(void) noexcept;
extern "C" void _isr201(void) noexcept;
extern "C" void _isr202(void) noexcept;
extern "C" void _isr203(void) noexcept;
extern "C" void _isr204(void) noexcept;
extern "C" void _isr205(void) noexcept;
extern "C" void _isr206(void) noexcept;
extern "C" void _isr207(void) noexcept;
extern "C" void _isr208(void) noexcept;
extern "C" void _isr209(void) noexcept;
extern "C" void _isr210(void) noexcept;
extern "C" void _isr211(void) noexcept;
extern "C" void _isr212(void) noexcept;
extern "C" void _isr213(void) noexcept;
extern "C" void _isr214(void) noexcept;
extern "C" void _isr215(void) noexcept;
extern "C" void _isr216(void) noexcept;
extern "C" void _isr217(void) noexcept;
extern "C" void _isr218(void) noexcept;
extern "C" void _isr219(void) noexcept;
extern "C" void _isr220(void) noexcept;
extern "C" void _isr221(void) noexcept;
extern "C" void _isr222(void) noexcept;
extern "C" void _isr223(void) noexcept;
extern "C" void _isr224(void) noexcept;
extern "C" void _isr225(void) noexcept;
extern "C" void _isr226(void) noexcept;
extern "C" void _isr227(void) noexcept;
extern "C" void _isr228(void) noexcept;
extern "C" void _isr229(void) noexcept;
extern "C" void _isr230(void) noexcept;
extern "C" void _isr231(void) noexcept;
extern "C" void _isr232(void) noexcept;
extern "C" void _isr233(void) noexcept;
extern "C" void _isr234(void) noexcept;
extern "C" void _isr235(void) noexcept;
extern "C" void _isr236(void) noexcept;
extern "C" void _isr237(void) noexcept;
extern "C" void _isr238(void) noexcept;
extern "C" void _isr239(void) noexcept;
extern "C" void _isr240(void) noexcept;
extern "C" void _isr241(void) noexcept;
extern "C" void _isr242(void) noexcept;
extern "C" void _isr243(void) noexcept;
extern "C" void _isr244(void) noexcept;
extern "C" void _isr245(void) noexcept;
extern "C" void _isr246(void) noexcept;
extern "C" void _isr247(void) noexcept;
extern "C" void _isr248(void) noexcept;
extern "C" void _isr249(void) noexcept;
extern "C" void _isr250(void) noexcept;
extern "C" void _isr251(void) noexcept;
extern "C" void _isr252(void) noexcept;
extern "C" void _isr253(void) noexcept;
extern "C" void _isr254(void) noexcept;
extern "C" void _isr255(void) noexcept;

#endif

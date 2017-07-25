//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Kyle Tempkin      <temkink@ainfosec.com>
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

#ifndef OBJECT_ALLOCATOR_H
#define OBJECT_ALLOCATOR_H

#include <bfgsl.h>
#include <bfexception.h>

// TODO:
//
// Once the buddy allocator is complete, this code should alloc from the
// buddy allocator and not g_mm.
//

#include <memory_manager/memory_manager_x64.h>

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr const auto pagepool_size = 255U;
constexpr const auto objtpool_size = 255U;

// -----------------------------------------------------------------------------
// Basic Allocator Definition
// -----------------------------------------------------------------------------

/// Basic Object Allocator
///
/// The goals of this allocator includes:
/// - O(1) allocation time
/// - O(1) deallocation time
/// - No external fragmentation (internal fragmentation is allowed, and can
///   be high depending on the size of the object)
/// - Pre-allocate backing store, or dynamically allocate backing store as
///   needed (depends on usage)
/// - All external allocations made by the object allocator are a page in size
///
/// To support these features, this allocator uses 4 different stacks.
/// - page stack: this stack stores a pool of page_t structures, each page_t
///   stores the address of a single page that can be used as a backing store
///   for allocations. Each page_stack_t can store 255 page_t structures before
///   another page_stack_t has to be pushed to the stack
/// - object stack: this stack stores all of the object_t structures. Each
///   object_stack_t can store 255 object_t structures before another
///   object_stack_t has to be pushed to the stack.
/// - free / used stacks: these stacks store the object_t structures based
///   on their current status. object_t structures ready to be allocated are
///   stored on the free stack, while object_t structures already allocated
///   are stored on the used stack. Each allocation / deallocation simply
///   moves a object_t structure from one stack to another.
///
/// In order to support both dynamic allocation, and limited pre-allocation
/// schemes (i.e. all memory is allocated ahead of time, and once this
/// pre-allocated memory is used, the allocator is out of memory), a max_pages
/// variable is defined. If set to 0, the max number of pages used by the
/// allocator is unlimited, and all allocations are performed dynamically
/// on demand. If set to > 0, all memory is pre-allocated and limited. Also
/// note that the max_pages refers to the total number of pages allocated for
/// use by the page pool, and does not include pages allocated for the
/// allocator's internal stacks.
///
/// Limitations
/// - The largest allocation that can take place is a page. Any
///   allocation larger than this should use the buddy allocator
/// - To achieve O(1) deallocation times, deallocation does not check the
///   validity of the provided pointer. If the pointer provided was not
///   previously allocated using the same allocator, corruption is likely.
///
/// TODO:
/// - Currently the allocator's internal stacks always grow. In the future,
///   code should be added to detect when resources are no longer needed and
///   free them.
///
/// Performance Notes:
/// - Like most allocators, if the object size is small, the overhead of
///   managing this memory is large and vice versa.
/// - When compared to GCC's default allocators for std::list, this allocator
///   outperforms with respect to both allocations, and deallocations with both
///   the limited and unlimited versions. Note that the unit tests use a
///   std::map to ensure memory is not leaked, resulting in additional overhead
///   not seen by the default allocators. A traditional malloc / free version
///   is provided that can be uncommented if needed
///
class basic_object_allocator
{
public:

    using pointer = void *;                                ///< Alloc::pointer
    using size_type = std::size_t;                         ///< Alloc::size_type

public:

    /// Constructor
    ///
    /// @expects size != 0
    /// @ensures none
    ///
    /// @param size the size of the object to allocate
    /// @param max_pages the max number of pages that may be used. 0 for
    ///     unlimitted
    ///
    basic_object_allocator(size_type size, size_type max_pages) noexcept :
        m_size(size),
        m_max_pages(max_pages)
    {
        expects(size != 0);

        guard_exceptions([&]() {

            if (max_pages != 0) {
                for (auto i = 0U; i < max_pages; i++) {
                    add_to_free_stack();
                }
            }

            bfdebug_info(1, "basic_object_allocator: constructed");
            bfdebug_subndec(1, "size", size);
            bfdebug_subndec(1, "max pages", max_pages);

            if (max_pages != 0) {
                bfdebug_subndec(1, "max objects", max_pages / size);
            }
            else {
                bfdebug_subtext(1, "max objects", "unlimited");
            }
        });
    }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~basic_object_allocator() noexcept
    { cleanup(); }

    /// Move Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    basic_object_allocator(basic_object_allocator &&other) noexcept
    { *this = std::move(other); }

    /// Move Operator
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    basic_object_allocator &operator=(basic_object_allocator &&other) noexcept
    {
        if (GSL_UNLIKELY(this != &other)) {

            cleanup();

            m_free_stack_top = other.m_free_stack_top;
            m_used_stack_top = other.m_used_stack_top;
            m_page_stack_top = other.m_page_stack_top;
            m_objt_stack_top = other.m_objt_stack_top;

            m_size = other.m_size;
            m_max_pages = other.m_max_pages;
            m_pages_consumed = other.m_pages_consumed;

            other.m_free_stack_top = nullptr;
            other.m_used_stack_top = nullptr;
            other.m_page_stack_top = nullptr;
            other.m_objt_stack_top = nullptr;

            other.m_size = 0;
            other.m_max_pages = 0;
            other.m_pages_consumed = 0;
        }

        return *this;
    }

    /// Allocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return an allocated object. Throws otherwise
    ///
    inline pointer allocate()
    {
        auto objt = free_stack_pop();
        used_stack_push(objt);

        return objt->addr;
    }

    /// Deallocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param p a pointer to a previously allocated object to be deallocated
    ///
    inline void deallocate(pointer p)
    {
        auto objt = used_stack_pop();
        free_stack_push(objt);

        objt->addr = p;
    }

    /// Get Page Stack Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return size of page stack
    ///
    inline auto page_stack_size() noexcept
    {
        auto size = 0ULL;
        auto next = m_page_stack_top;

        while (next != nullptr) {
            size++;
            next = next->next;
        }

        return size;
    }

    /// Get Object Stack Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return size of object stack
    ///
    inline auto objt_stack_size() noexcept
    {
        auto size = 0ULL;
        auto next = m_objt_stack_top;

        while (next != nullptr) {
            size++;
            next = next->next;
        }

        return size;
    }

    /// Get Number of Allocated Pages
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of allocated pages
    ///
    inline auto num_page() noexcept
    {
        auto size = 0ULL;
        auto next = m_page_stack_top;

        while (next != nullptr) {
            size += next->index;
            next = next->next;
        }

        return size;
    }

    /// Get Free List Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of object_t structures in free list
    ///
    inline auto num_free() noexcept
    {
        auto size = 0ULL;
        auto next = m_free_stack_top;

        while (next != nullptr) {
            size++;
            next = next->next;
        }

        return size;
    }

    /// Get Free Used Size
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @return number of object_t structures in used list
    ///
    inline auto num_used() noexcept
    {
        auto size = 0ULL;
        auto next = m_used_stack_top;

        while (next != nullptr) {
            size++;
            next = next->next;
        }

        return size;
    }

private:

    struct object_t {
        pointer addr;
        object_t *next;
    };

    struct object_stack_t {
        object_t pool[objtpool_size];

        uint64_t index;
        object_stack_t *next;
    };

    struct page_t {
        gsl::byte *addr;
        uint64_t index;
    };

    struct page_stack_t {
        page_t pool[pagepool_size];

        uint64_t index;
        page_stack_t *next;
    };

    object_t *m_free_stack_top{nullptr};
    object_t *m_used_stack_top{nullptr};

    page_stack_t *m_page_stack_top{nullptr};
    object_stack_t *m_objt_stack_top{nullptr};

private:

    template<typename S>
    S *alloc_struct()
    {
        pointer addr;

        if (GSL_LIKELY(addr = g_mm->alloc(sizeof(S)))) {
            return static_cast<S *>(std::memset(addr, 0, sizeof(S)));
        }

        throw std::runtime_error("alloc_struct: out of memory");
    }

    inline page_t *get_next_page()
    {
        if (GSL_UNLIKELY(m_max_pages != 0 && m_pages_consumed >= m_max_pages)) {
            throw std::runtime_error("object_allocator: out of memory");
        }

        if (m_page_stack_top == nullptr || m_page_stack_top->index == pagepool_size) {
            expand_page_stack();
        }

        auto page = &gsl::at(m_page_stack_top->pool, m_page_stack_top->index);
        page->addr = static_cast<gsl::byte *>(g_mm->alloc(0x1000));
        page->index = 0;

        ++m_pages_consumed;
        ++m_page_stack_top->index;

        return page;
    }

    inline object_t *get_next_object()
    {
        if (m_objt_stack_top == nullptr || m_objt_stack_top->index == objtpool_size) {
            expand_object_stack();
        }

        return &gsl::at(m_objt_stack_top->pool, m_objt_stack_top->index++);
    }

    inline void free_stack_push(object_t *next)
    {
        next->next = m_free_stack_top;
        m_free_stack_top = next;
    }

    inline object_t *free_stack_pop()
    {
        if (m_free_stack_top == nullptr) {
            add_to_free_stack();
        }

        auto top = m_free_stack_top;

        m_free_stack_top = m_free_stack_top->next;
        top->next = nullptr;

        return top;
    }

    inline void used_stack_push(object_t *next)
    {
        next->next = m_used_stack_top;
        m_used_stack_top = next;
    }

    inline object_t *used_stack_pop()
    {
        if (GSL_UNLIKELY(m_used_stack_top == nullptr)) {
            throw std::runtime_error("used stack empty");
        }

        auto top = m_used_stack_top;

        m_used_stack_top = m_used_stack_top->next;
        top->next = nullptr;

        return top;
    }

    inline void expand_page_stack()
    {
        auto next = alloc_struct<page_stack_t>();

        next->next = m_page_stack_top;
        m_page_stack_top = next;
    }

    inline void expand_object_stack()
    {
        auto next = alloc_struct<object_stack_t>();

        next->next = m_objt_stack_top;
        m_objt_stack_top = next;
    }

    inline void add_to_free_stack()
    {
        auto page = get_next_page();

        for (auto i = 0ULL; i < 0x1000; i += m_size) {
            auto object = get_next_object();
            free_stack_push(object);

            object->addr = &gsl::at(page->addr, 0x1000, i);
        }
    }

    inline void cleanup() noexcept
    {
        guard_exceptions([&]() {

            bfdebug_ndec(1, "basic_object_allocator: pages used", num_page());

            while (m_page_stack_top != nullptr) {
                if (m_page_stack_top->index != 0) {
                    for (auto i = 0ULL; i < m_page_stack_top->index; i++) {
                        auto page = &gsl::at(m_page_stack_top->pool, i);
                        g_mm->free(page->addr);
                    }
                }

                auto next = m_page_stack_top->next;
                g_mm->free(m_page_stack_top);
                m_page_stack_top = next;
            }

            while (m_objt_stack_top != nullptr) {
                auto next = m_objt_stack_top->next;
                g_mm->free(m_objt_stack_top);
                m_objt_stack_top = next;
            }

            m_free_stack_top = nullptr;
            m_used_stack_top = nullptr;
            m_page_stack_top = nullptr;
            m_objt_stack_top = nullptr;

            m_size = 0;
            m_max_pages = 0;
            m_pages_consumed = 0;
        });
    }

private:

    size_type m_size{0};
    size_type m_max_pages{0};
    size_type m_pages_consumed{0};

public:

    /// @cond

    basic_object_allocator(const basic_object_allocator &) = delete;
    basic_object_allocator &operator=(const basic_object_allocator &) = delete;

    /// @endcond
};

// -----------------------------------------------------------------------------
// Allocator Definition
// -----------------------------------------------------------------------------

/// Object Allocator
///
/// This is a C++ Allocator wrapper for the basic_object_allocator that conforms
/// to the allocator concept defined here:
/// http://en.cppreference.com/w/cpp/concept/Allocator
///
/// Note that rebind allows a std container to create a new allocator based on
/// the one provided as is needed. For example, std containers will not only
/// have to allocate T, but they will also have to allocate nodes. In some
/// cases, the implementation will embed T in the node resulting in only a
/// single allocation for each T, that is larger than T (consisting of the
/// extra overhead needed by the container). For this reason, max_pages should
/// be chosen to not only account for sizeof(T) but also a potential
/// sizeof(node<T>).
///
/// There are a couple of limitations with this wrapper. The copy constructor
/// is not supported as the allocator is stateful, and thus two of the same
/// allocators cannot exist. Also, 'n' is not supported for the allocation and
/// deallocation functions, or in other words, n must always equal 1. For this
/// reason, this allocator should not be used with containers like std::deque
/// which rely on n != 1 to increase efficiency of the standard use cases.
///
template<typename T, std::size_t max_pages = 0>
class object_allocator
{
public:

    using value_type = T;                                               ///< Alloc::value_type
    using pointer = T *;                                                ///< Alloc::pointer
    using const_pointer = const T *;                                    ///< Alloc::const_pointer
    using size_type = std::size_t;                                      ///< Alloc::size_type
    using propagate_on_container_copy_assignment = std::false_type;     ///< Copy not supported
    using propagate_on_container_move_assignment = std::true_type;      ///< Move supported
    using propagate_on_container_swap = std::true_type;                 ///< Swap supported
    using is_always_equal = std::false_type;                            ///< Not always equal

    template<typename U> struct rebind {
        using other = object_allocator<U, max_pages>;
    };

    static_assert(0x1000 >= sizeof(T), "T is too large");

public:

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    object_allocator() noexcept :
        m_d {sizeof(T), max_pages}
    { }

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~object_allocator() noexcept
    { }

    /// Move Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    object_allocator(object_allocator &&other) noexcept :
        m_d {std::move(other.m_d)}
    { }

    /// Move Operator
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other the allocator to move from
    ///
    object_allocator &operator=(object_allocator &&other) noexcept
    {
        m_d = std::move(other.m_d);
        return *this;
    }

    /// Copy Constructor (not supported)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    ///
    object_allocator(const object_allocator &other) noexcept
    { }

    /// Copy Constructor (not supported)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    ///
    template <typename U>
    object_allocator(const object_allocator<U, max_pages> &other) noexcept
    { }

    /// Copy Operator (not supported)
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param other not supported
    ///
    object_allocator &operator=(const object_allocator &other) noexcept
    { }

    /// Allocate
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param n not supported
    /// @return an allocated object. Throws otherwise
    ///
    pointer allocate(size_type n)
    {
        bfignored(n);
        return static_cast<pointer>(m_d.allocate());
    }

    /// Deallocate Object
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param n not supported
    /// @param p a pointer to a previously allocated object to be deallocated
    ///
    void deallocate(pointer p, size_type n)
    {
        bfignored(n);
        m_d.deallocate(p);
    }

public:

    /// @cond

    auto page_stack_size() noexcept
    { return m_d.page_stack_size(); }

    auto objt_stack_size() noexcept
    { return m_d.objt_stack_size(); }

    auto num_page() noexcept
    { return m_d.num_page(); }

    auto num_free() noexcept
    { return m_d.num_free(); }

    auto num_used() noexcept
    { return m_d.num_used(); }

    /// @endcond

private:

    basic_object_allocator m_d;

private:

    template <typename T1, typename T2, std::size_t MP>
    friend bool operator==(const object_allocator<T1, MP> &lhs, const object_allocator<T2, MP> &rhs);

    template <typename T1, typename T2, std::size_t MP>
    friend bool operator!=(const object_allocator<T1, MP> &lhs, const object_allocator<T2, MP> &rhs);
};

/// @cond

template <typename T1, typename T2, std::size_t MP>
bool operator==(const object_allocator<T1, MP> &, const object_allocator<T2, MP> &)
{ return false; }

template <typename T1, typename T2, std::size_t MP>
bool operator!=(const object_allocator<T1, MP> &, const object_allocator<T2, MP> &)
{ return true; }

/// @endcond

#endif

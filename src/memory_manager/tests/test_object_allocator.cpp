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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <map>
#include <list>
#include <queue>
#include <memory>

#include <bfgsl.h>
#include <bfbenchmark.h>
#include <memory_manager/object_allocator.h>

constexpr const auto blocks_per_page = 512;

std::map<memory_manager_x64::pointer, std::unique_ptr<gsl::byte[]>> g_allocated_memory;

memory_manager_x64::pointer
test_alloc(memory_manager_x64::size_type size) noexcept
{
    expects(size == 0x1000);

    auto mem = std::make_unique<gsl::byte[]>(size);
    auto ptr = mem.get();

    g_allocated_memory[ptr] = std::move(mem);
    return ptr;
}

void
test_free(memory_manager_x64::pointer ptr) noexcept
{
    g_allocated_memory.erase(ptr);
}

// memory_manager_x64::pointer
// test_alloc(memory_manager_x64::size_type size) noexcept
// { return malloc(size); }

// void
// test_free(memory_manager_x64::pointer ptr) noexcept
// { free(ptr); }

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::alloc).Do(test_alloc);
    mocks.OnCall(mm, memory_manager_x64::free).Do(test_free);

    return mm;
}

TEST_CASE("construction: limited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool{};

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("construction: unlimited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        CHECK(pool.page_stack_size() == 0);
        CHECK(pool.objt_stack_size() == 0);
        CHECK(pool.num_page() == 0);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: single allocation")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: multiple allocations")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            CHECK_NOTHROW(pool.allocate(1));
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page * 4);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: over limit")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool{};

        for (auto i = 0; i < blocks_per_page; i++) {
            CHECK_NOTHROW(pool.allocate(1));
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page);

        CHECK_THROWS(pool.allocate(1));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("deallocate: deallocate without allocate")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        uint64_t nothing = 0;
        object_allocator<uint64_t> pool{};

        CHECK_THROWS(pool.deallocate(&nothing, 1));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("deallocate: deallocate single allocation")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        auto alloc = pool.allocate(1);

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);

        CHECK_NOTHROW(pool.deallocate(alloc, 1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("deallocate: deallocate multiple allocations")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        std::list<uint64_t *> v{};
        object_allocator<uint64_t> pool{};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            v.push_back(pool.allocate(1));
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page * 4);

        for (auto elem : v) {
            pool.deallocate(elem, 1);
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == blocks_per_page * 4);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("max_size: can allocate max_size")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        struct test {
            gsl::byte data[0x1000];
        };

        object_allocator<test> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 1);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("max_size: can allocate max_size more than once")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        struct test {
            gsl::byte data[0x1000];
        };

        object_allocator<test> pool{};

        CHECK_NOTHROW(pool.allocate(1));
        CHECK_NOTHROW(pool.allocate(1));
        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 3);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 3);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: unlimited are not equal")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: limited are not equal")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 1> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: move unlimited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        pool1 = std::move(pool2);

        CHECK(pool1.page_stack_size() == 0);
        CHECK(pool1.objt_stack_size() == 0);
        CHECK(pool1.num_page() == 0);
        CHECK(pool1.num_free() == 0);
        CHECK(pool1.num_used() == 0);

        CHECK(pool2.page_stack_size() == 0);
        CHECK(pool2.objt_stack_size() == 0);
        CHECK(pool2.num_page() == 0);
        CHECK(pool2.num_free() == 0);
        CHECK(pool2.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: move limited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 1> pool2{};

        pool1 = std::move(pool2);

        CHECK(pool1.page_stack_size() == 1);
        CHECK(pool1.objt_stack_size() == 3);
        CHECK(pool1.num_page() == 1);
        CHECK(pool1.num_free() == blocks_per_page);
        CHECK(pool1.num_used() == 0);

        CHECK(pool2.page_stack_size() == 0);
        CHECK(pool2.objt_stack_size() == 0);
        CHECK(pool2.num_page() == 0);
        CHECK(pool2.num_free() == 0);
        CHECK(pool2.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

constexpr const auto NUM_ITERATIONS = 0x1000U;

TEST_CASE("unlimited queue")
{
    MockRepository mocks;
    setup_mm(mocks);

    bfdebug_info(0, "unlimited queue");
    {
        std::queue<uint64_t, std::list<uint64_t, object_allocator<uint64_t>>> d;

        bfdebug_subndec(0, "push #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));

        bfdebug_subndec(0, "pop #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.pop();
            }
        }));

        bfdebug_subndec(0, "push #2", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("limited queue")
{
    MockRepository mocks;
    setup_mm(mocks);

    bfdebug_info(0, "limited queue");
    {
        std::queue<uint64_t, std::list<uint64_t, object_allocator<uint64_t, 100000>>> d;

        bfdebug_subndec(0, "push #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));

        bfdebug_subndec(0, "pop #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.pop();
            }
        }));

        bfdebug_subndec(0, "push #2", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("base line")
{
    MockRepository mocks;
    setup_mm(mocks);

    bfdebug_info(0, "base line");
    {
        std::queue<uint64_t, std::list<uint64_t>> d;

        bfdebug_subndec(0, "push #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));

        bfdebug_subndec(0, "pop #1", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.pop();
            }
        }));

        bfdebug_subndec(0, "push #2", benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            {
                d.push(i);
            }
        }));
    }

    CHECK(g_allocated_memory.empty());
}

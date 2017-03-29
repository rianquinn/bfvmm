[![GitHub version](https://badge.fury.io/gh/Bareflank%2Fbfvmm.svg)](https://badge.fury.io/gh/Bareflank%2Fbfvmm)
[![Build Status](https://travis-ci.org/Bareflank/bfvmm.svg?branch=master)](https://travis-ci.org/Bareflank/bfvmm)
[![Build status](https://ci.appveyor.com/api/projects/status/li2lg7f5pb8gkqos/branch/master?svg=true)](https://ci.appveyor.com/project/rianquinn/bfvmm/branch/master)
[![codecov](https://codecov.io/gh/Bareflank/bfvmm/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/bfvmm)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/bf7708c3eacc4f11ad6c7ddaeb3ed64e)](https://www.codacy.com/app/rianquinn/bfvmm?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Bareflank/bfvmm&amp;utm_campaign=Badge_Grade)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/325/badge)](https://bestpractices.coreinfrastructure.org/projects/325)
[![Join the chat at https://gitter.im/Bareflank-hypervisor/Lobby](https://badges.gitter.im/Bareflank-hypervisor/Lobby.svg)](https://gitter.im/Bareflank-hypervisor/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

## Description

The Bareflank Virtual Machine Monitor (VMM) is the part of the hypervisor that
monitors each virtual machine. The term "hypervisor" can mean a lot of things.
Generally speaking, it should refer to the piece of code that maintains control
of the supervisor, but instead generally refers  to everything within a
hypervisor's project including the drivers and userspace code (e.g. the Xen
hypervisor is made up of everything from the actual hypervisor itself, but also
its hypercall libraries, libXL, etc...). Thus, the Bareflank hypervisor
describes the entire project, while the VMM is the piece of code that oversees
the management of each virtual machine, and the "exit handler", which is
contained in the VMM, is the actual piece of code that maintains control
over the supervisor with so called "ring -1" privileges.

/**
 * Core.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */
 
#pragma once

#if __has_include("core.h")
#include <core.h>
#else
#error "Orbital depends on an unreleased third-party library and cannot be built without the required <core.h> header. \
    Functionality related to PS4 emulation/introspection is open-sourced *only* as documentation for fellow developers and hackers. \
    To build Orbital, wait for the upcoming release of <core.h> or reimplement your own by forwarding function calls to QEMU. \
    Please do NOT ask for help/support related to <core.h> issues."
#endif

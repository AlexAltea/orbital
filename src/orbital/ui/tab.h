/**
 * UI tab.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#define IMGUI_IMPL_API
#include <imgui.h>
#include "imgui/widgets/imgui_memory_editor.h"

class Tab {
public:
    // Interface
    void begin_dockspace();
    void end_dockspace();
};

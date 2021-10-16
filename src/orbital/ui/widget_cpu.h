/**
 * UI widget for CPU debugging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <core.h>

#include <cstdint>

#define IMGUI_IMPL_API
#include <imgui.h>
#include "imgui/widgets/imgui_memory_editor.h"

 // Forward declarations
class PS4Machine;

class WidgetCPU {
public:
    WidgetCPU();

    // Interface
    void set_font_code(ImFont* font_code) {
        this->font_code = font_code;
    }
    void render(PS4Machine& ps4);

private:
    ImFont* font_code;
    MemoryEditor me_stack;
    MemoryEditor me_memory;
    size_t cs_x86_16;
    size_t cs_x86_32;
    size_t cs_x86_64;

    // State
    size_t cpu_index = 0;
    uint64_t view_stack = 0;
    uint64_t view_memory = 0;

    // Helpers
    void render_disasm(X86CPUDevice* c);
    void render_state(X86CPUDevice* c);
    void render_stack(X86CPUDevice* c);
    void render_memory(X86CPUDevice* c);
};

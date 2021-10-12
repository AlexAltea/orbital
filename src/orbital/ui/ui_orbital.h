/**
 * Orbital UI renderer for ImGui.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include "widget_cpu.h"

#define IMGUI_IMPL_API
#include <imgui.h>

#include <vector>

// Forward declarations
class PS4Machine;

class OrbitalUI {
public:
    // Interface
    void init();
    void render(PS4Machine& ps4);

private:
    // Fonts
    ImFont* font_default{};
    ImFont* font_text{};
    ImFont* font_code{};
    std::vector<std::uint8_t> font_text_data;
    std::vector<std::uint8_t> font_code_data;

    // Widgets
    WidgetCPU widget_cpu;

    // State
    bool show_stats;
    bool show_uart;
    bool show_gpu_debugger;
    bool show_executing_processes;
    bool show_process_list;
    bool show_trace_cp;
    bool show_trace_icc;
    bool show_trace_samu;
    bool show_mem_gpa;
    bool show_mem_gva;
    bool show_mem_gart;
    bool show_mem_iommu;

    // Helpers
    void render_dockspace();
    void render_menus(PS4Machine& ps4);
};

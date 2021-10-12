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

#define IMGUI_IMPL_API
#include <imgui.h>

#include <vector>

class OrbitalUI {
public:
    // Initialization
    void init();

    // Interface
    void render();

private:
    // Fonts
    ImFont* font_default{};
    ImFont* font_text{};
    ImFont* font_code{};
    std::vector<std::uint8_t> font_text_data;
    std::vector<std::uint8_t> font_code_data;

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
    void render_menus();
};

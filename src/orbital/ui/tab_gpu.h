/**
 * UI tab for GPU debugging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include "tab.h"

#define IMGUI_IMPL_API
#include <imgui.h>
#include "imgui/widgets/imgui_memory_editor.h"

 // Forward declarations
class PS4Machine;
class LiverpoolGCDevice;

class TabGPU : public Tab {
public:
    friend PS4Machine;
    TabGPU();

    // Interface
    void set_font_code(ImFont* font_code) {
        this->font_code = font_code;
    }
    void render(PS4Machine& ps4);

private:
    ImFont* font_code;

    // Helpers
    void render_dce(const LiverpoolGCDevice& c);
    void render_gfx(const LiverpoolGCDevice& c);
    void render_sam(const LiverpoolGCDevice& c);
};

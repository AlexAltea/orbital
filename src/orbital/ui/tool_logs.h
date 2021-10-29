/**
 * UI tool for text logging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

#define IMGUI_IMPL_API
#include <imgui.h>

// Forward declarations
class ImguiCharHost;

class ToolLogs {
public:
    ToolLogs();

    CharHost* backend() {
        return reinterpret_cast<CharHost*>(Backend);
    }

    void Clear();
    void Log(const char* fmt, ...);
    void Log(char c);
    void Draw(const char* title, bool* p_open = nullptr);

private:
    ImguiCharHost*      Backend;
    ImGuiTextBuffer     Buf;
    ImGuiTextFilter     Filter;
    ImVector<int>       LineOffsets;
    bool                ScrollToBottom;
};

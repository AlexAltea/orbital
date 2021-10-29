/**
 * UI tool for text logging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "tool_logs.h"
#include "charhost_imgui.h"

ToolLogs::ToolLogs() {
    Backend = new ImguiCharHost(nullptr, { this });
}

void ToolLogs::Clear() {
    Buf.clear();
    LineOffsets.clear();
}

void ToolLogs::Log(const char* fmt, ...) IM_FMTARGS(2) {
    int old_size = Buf.size();
    va_list args;
    va_start(args, fmt);
    Buf.appendfv(fmt, args);
    va_end(args);
    for (int new_size = Buf.size(); old_size < new_size; old_size++)
        if (Buf[old_size] == '\n')
            LineOffsets.push_back(old_size);
    ScrollToBottom = true;
}

void ToolLogs::Log(char c) {
    ImVector<char>& chars = Buf.Buf;
    if (c == '\n')
        LineOffsets.push_back(Buf.size());
    chars.push_back(c);
    ScrollToBottom = true;
}

void ToolLogs::Draw(const char* title, bool* p_open) {
    ImGui::SetNextWindowSize(ImVec2(500,400), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(title, p_open)) {
        ImGui::End();
        return;
    }
    if (ImGui::Button("Clear")) Clear();
    ImGui::SameLine();
    bool copy = ImGui::Button("Copy");
    ImGui::SameLine();
    Filter.Draw("Filter", -100.0f);
    ImGui::Separator();
    ImGui::BeginChild("scrolling", ImVec2(0,0), false, ImGuiWindowFlags_HorizontalScrollbar);
    if (copy) ImGui::LogToClipboard();

    if (Filter.IsActive()) {
        const char* buf_begin = Buf.begin();
        const char* line = buf_begin;
        for (int line_no = 0; line != NULL; line_no++) {
            const char* line_end = (line_no < LineOffsets.Size) ? buf_begin + LineOffsets[line_no] : NULL;
            if (Filter.PassFilter(line, line_end))
                ImGui::TextUnformatted(line, line_end);
            line = line_end && line_end[1] ? line_end + 1 : NULL;
        }
    } else {
        ImGui::TextUnformatted(Buf.begin());
    }

    if (ScrollToBottom)
        ImGui::SetScrollHereY(1.0f);
    ScrollToBottom = false;
    ImGui::EndChild();
    ImGui::End();
}

/**
 * UI tab.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "tab.h"

#define IMGUI_IMPL_API
#include <imgui.h>

void Tab::begin_dockspace() {
    ImGui::SetNextWindowSize(ImVec2(400.0f, 400.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.7f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.0f, 0.0f, 0.0f, 0.7f));
    ImGui::BeginChild("dockspace");
    ImGui::PopStyleColor(2);
    ImGui::PushStyleColor(ImGuiCol_DockingEmptyBg, ImVec4(1.0f, 0.0f, 0.0f, 0.0f));
    ImGuiID dockspace_id = ImGui::GetID("dockspace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), 0);
    ImGui::PopStyleColor();
}

void Tab::end_dockspace() {
    ImGui::EndChild();
}

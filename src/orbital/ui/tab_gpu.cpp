/**
 * UI tab for GPU debugging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "tab_gpu.h"
#include <orbital/hardware/ps4.h>

#define IMGUI_IMPL_API
#include <imgui.h>

#include <orbital/hardware/liverpool/dce/dce_8_0_d.h>
#include <orbital/hardware/liverpool/liverpool_gc.h>

enum {
    ATTR_U32_HEX,
    ATTR_U32_DEC,
};

struct dcp_attribute_t {
    int type;
    const char* name;
    int mmio_indices[6];
};

constexpr auto DCP_COUNT  = 6;
constexpr auto CRTC_COUNT = 6;

#define DCP_ATTR(t, x) \
    { t, #x, { mmDCP0_##x, mmDCP1_##x, mmDCP2_##x, \
               mmDCP3_##x, mmDCP4_##x, mmDCP5_##x }}

std::array<dcp_attribute_t, 11> dcp_attrs = { {
    DCP_ATTR(ATTR_U32_HEX, GRPH_PRIMARY_SURFACE_ADDRESS),
    DCP_ATTR(ATTR_U32_HEX, GRPH_PRIMARY_SURFACE_ADDRESS_HIGH),
    DCP_ATTR(ATTR_U32_HEX, GRPH_SECONDARY_SURFACE_ADDRESS),
    DCP_ATTR(ATTR_U32_HEX, GRPH_SECONDARY_SURFACE_ADDRESS_HIGH),
    DCP_ATTR(ATTR_U32_DEC, GRPH_PITCH),
    DCP_ATTR(ATTR_U32_DEC, GRPH_SURFACE_OFFSET_X),
    DCP_ATTR(ATTR_U32_DEC, GRPH_SURFACE_OFFSET_Y),
    DCP_ATTR(ATTR_U32_DEC, GRPH_X_START),
    DCP_ATTR(ATTR_U32_DEC, GRPH_Y_START),
    DCP_ATTR(ATTR_U32_DEC, GRPH_X_END),
    DCP_ATTR(ATTR_U32_DEC, GRPH_Y_END),
} };

TabGPU::TabGPU() {
}

void TabGPU::render(PS4Machine& ps4) {
    auto& gc = ps4.gc();

    begin_dockspace();
    if (ImGui::Begin("DCE")) {
        render_dce(gc);
    }
    ImGui::End();
    if (ImGui::Begin("GFX")) {
        render_gfx(gc);
    }
    ImGui::End();
    if (ImGui::Begin("SAM")) {
        render_sam(gc);
    }
    ImGui::End();
    end_dockspace();
}

void TabGPU::render_dce(const LiverpoolGCDevice& gc) {
    auto mmio = gc.get_mmio();
    const uint32_t u32_one = 1;
    char tag[256];

    if (ImGui::CollapsingHeader("DCP")) {
        ImGui::Columns(DCP_COUNT + 1, "DCP_Columns");
        ImGui::Separator();
        ImGui::Text("Attribute");
        ImGui::NextColumn();
        for (int i = 0; i < DCP_COUNT; i++) {
            ImGui::Text("DCP%d", i);
            ImGui::NextColumn();
        }
        ImGui::Separator();
        for (const auto& attr : dcp_attrs) {
            ImGui::Text("%s", attr.name);
            ImGui::NextColumn();
            for (int i = 0; i < DCP_COUNT; i++) {
                int mm_index = attr.mmio_indices[i];
                snprintf(tag, sizeof(tag), "##dcp%d_%s", i, attr.name);
                switch (attr.type) {
                case ATTR_U32_DEC:
                    ImGui::PushItemWidth(-1);
                    ImGui::InputScalar(tag, ImGuiDataType_U32, &mmio[mm_index], &u32_one, NULL, "%d",
                        ImGuiInputTextFlags_CharsDecimal |
                        ImGuiInputTextFlags_ReadOnly);
                    ImGui::PopItemWidth();
                    break;
                case ATTR_U32_HEX:
                    ImGui::PushItemWidth(-1);
                    ImGui::InputScalar(tag, ImGuiDataType_U32, &mmio[mm_index], NULL, NULL, "0x%08X",
                        ImGuiInputTextFlags_CharsHexadecimal |
                        ImGuiInputTextFlags_CharsUppercase |
                        ImGuiInputTextFlags_ReadOnly);
                    ImGui::PopItemWidth();
                    break;
                default:
                    ImGui::Text("???");
                }
                ImGui::NextColumn();
            }
        }
        ImGui::Columns(1);
        ImGui::Separator();
    }
    if (ImGui::CollapsingHeader("CRTC")) {
        ImGui::Columns(DCP_COUNT + 1, "CRTC_Columns");
        ImGui::Separator();
        ImGui::Text("Attribute");
        ImGui::NextColumn();
        for (int i = 0; i < CRTC_COUNT; i++) {
            ImGui::Text("CRTC%d", i);
            ImGui::NextColumn();
        }
        ImGui::Columns(1);
        ImGui::Separator();
    }
}

void TabGPU::render_gfx(const LiverpoolGCDevice& gc) {
}

void TabGPU::render_sam(const LiverpoolGCDevice& gc) {
}

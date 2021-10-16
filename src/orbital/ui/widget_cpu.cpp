/**
 * UI widget for CPU debugging.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "widget_cpu.h"
#include <orbital/hardware/ps4.h>

#include <core.h>
#include <capstone/capstone.h>
#include <fmt/format.h>

#define IMGUI_IMPL_API
#include <imgui.h>

#include <string>

static std::string cpu_name(size_t index) {
    return "CPU #" + std::to_string(index);
}

WidgetCPU::WidgetCPU() {
    // Initialize Capstone engine
    if (!cs_support(CS_ARCH_X86)) {
        throw std::runtime_error("Capstone library compiled without x86/64 support!");
    }
    cs_open(CS_ARCH_X86, CS_MODE_16, &cs_x86_16);
    cs_open(CS_ARCH_X86, CS_MODE_32, &cs_x86_32);
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs_x86_64);
}

void WidgetCPU::render(PS4Machine& ps4) {
    const auto cpu_count = ps4.count<X86CPUDevice>();
    if (cpu_index >= cpu_count) {
        cpu_index = 0;
    }

    //ImGui::SetNextWindowDockID(ImGui::GetID("dockspace"), ImGuiCond_Always);
    if (ImGui::Begin("CPU")) {
        // CPU selector
        if (ImGui::BeginCombo("##cpu_selector", cpu_name(cpu_index).c_str())) {
            for (size_t i = 0; i < cpu_count; i++) {
                if (ImGui::Selectable(cpu_name(i).c_str(), cpu_index == i)) {
                    cpu_index = i;
                }
            }
            ImGui::EndCombo();
        }

        // Get pointer to selected CPU
        X86CPUDevice* x86cpu = nullptr;
        size_t i = 0;
        for (auto& cpu : ps4.get_iterable_member<CPUDevice>()) {
            if (i++ == cpu_index) {
                x86cpu = dynamic_cast<X86CPUDevice*>(cpu);
            }
        }

        // CPU control toolbar
        if (x86cpu->is_running()) {
            ImGui::SameLine();
            if (ImGui::Button("Pause")) {
                x86cpu->request_pause();
            }
        } else {
            ImGui::SameLine();
            if (ImGui::Button("Resume")) {
                x86cpu->request_resume();
            }
            ImGui::SameLine();
            if (ImGui::Button("Step")) {
                x86cpu->request_step();
            }
        }

        render_disasm(x86cpu);
        render_state(x86cpu);
        render_stack(x86cpu);
        render_memory(x86cpu);
    }
    ImGui::End();
}

void WidgetCPU::render_disasm(X86CPUDevice* c) {
    // Select Capstone engine base on CPU mode
    csh cs;
    switch (c->mode()) {
    case X86CPUMode::REAL:
        cs = cs_x86_16;
        break;
    case X86CPUMode::PROTECTED:
    case X86CPUMode::LONG_COMPATIBILITY:
        if (c->state().cs.db)
            cs = cs_x86_32;
        else
            cs = cs_x86_16;
        break;
    case X86CPUMode::LONG_64_BIT:
    default:
        cs = cs_x86_64;
        break;
    }

    // Read instructions
    constexpr size_t insn_maxsize = 16;
    constexpr size_t insn_maxshow = 128;
    Buffer buf(insn_maxshow * insn_maxsize);
    const auto& state = c->state();
    const auto& space = c->space();
    const auto rip = state.get_linear_rip();
    try {
        space->read(rip, buf.size(), buf.data());
    } catch (std::runtime_error& e) {
        g_error("Error: {}", e.what());
        return;
    }

    // Diassemble and present content
    if (ImGui::Begin("Disassembly", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        cs_insn* insns = nullptr;
        size_t insn_count = cs_disasm(cs, buf.data(), buf.size(), rip, insn_maxshow, &insns);

        ImGui::PushFont(font_code);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, { 4, 1 });
        for (size_t i = 0; i < insn_count; i++) {
            const auto insn = insns[i];
            std::string line;

            // Show address
            line += (insn.address == rip) ? "> " : "  ";
            line += fmt::format("{:08X} ", insn.address);
            line += "    ";

            // Show bytes
            constexpr size_t bytes_maxshow = 5;
            for (size_t j = 0; j < bytes_maxshow; j++) {
                line += (j < insn.size) ? fmt::format("{:02X} ", insn.bytes[j]) : "   ";
            }
            line += "    ";

            // Show disassembly
            line += fmt::format("{:<8s} {}", insn.mnemonic, insn.op_str);

            if (ImGui::Selectable(line.c_str())) {
            }
        }
        ImGui::PopStyleVar();
        ImGui::PopFont();
        cs_free(insns, insn_count);
    }
    ImGui::End();
}

void WidgetCPU::render_state(X86CPUDevice* c) {
    if (ImGui::Begin("State")) {
        const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg;
        if (ImGui::BeginTable("Registers", 2, flags)) {
            ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Value");
            ImGui::TableHeadersRow();
            ImGui::PushFont(font_code);

            auto add_register = [](const char* name, auto value) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text(name);
                ImGui::TableSetColumnIndex(1);
                if constexpr (sizeof(value) == 2) {
                    ImGui::Text("%04X", value);
                }
                if constexpr (sizeof(value) == 4) {
                    ImGui::Text("%08X", value);
                }
                if constexpr (sizeof(value) == 8) {
                    ImGui::Text("%016llX", value);
                }
            };
            const auto& state = c->state();
            switch (c->mode()) {
            case X86CPUMode::REAL:
            case X86CPUMode::PROTECTED:
            case X86CPUMode::LONG_COMPATIBILITY:
                add_register("eax", state.eax);
                add_register("ecx", state.ecx);
                add_register("edx", state.edx);
                add_register("ebx", state.ebx);
                add_register("esp", state.esp);
                add_register("ebp", state.ebp);
                add_register("esi", state.esi);
                add_register("edi", state.edi);
                add_register("eip", state.eip);
                break;
            case X86CPUMode::LONG_64_BIT:
            default:
                add_register("rax", state.rax);
                add_register("rcx", state.rcx);
                add_register("rdx", state.rdx);
                add_register("rbx", state.rbx);
                add_register("rsp", state.rsp);
                add_register("rbp", state.rbp);
                add_register("rsi", state.rsi);
                add_register("rdi", state.rdi);
                add_register("r8",  state.r8);
                add_register("r9",  state.r9);
                add_register("r10", state.r10);
                add_register("r11", state.r11);
                add_register("r12", state.r12);
                add_register("r13", state.r13);
                add_register("r14", state.r14);
                add_register("r15", state.r15);
                add_register("rip", state.rip);
                break;
            }
            ImGui::PopFont();
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

void WidgetCPU::render_stack(X86CPUDevice* c) {
    const auto& state = c->state();
    const auto& space = c->space();

    // Read stack contents
    Buffer buf(0x100);
    const auto rsp = state.get_linear_rsp();
    try {
        space->read(rsp, buf.size(), buf.data());
    } catch (std::runtime_error& e) {
        g_error("Error: {}", e.what());
        return;
    }

    // Adjust stack view width
    switch (c->mode()) {
    case X86CPUMode::REAL:
    case X86CPUMode::PROTECTED:
    case X86CPUMode::LONG_COMPATIBILITY:
        me_stack.Cols = 4;
        break;
    case X86CPUMode::LONG_64_BIT:
    default:
        me_stack.Cols = 8;
        break;
    }

    if (ImGui::Begin("Stack")) {
        ImGui::PushFont(font_code);    
        me_stack.DrawContents(buf.data(), buf.size(), rsp);
        ImGui::PopFont();
    }
    ImGui::End();
}

void WidgetCPU::render_memory(X86CPUDevice* c) {
    const auto& state = c->state();
    const auto& space = c->space();

    // Read stack contents
    Buffer buf(0x1000);
    const auto addr = 0x9D000;
    try {
        space->read(addr, buf.size(), buf.data());
    }
    catch (std::runtime_error& e) {
        g_error("Error: {}", e.what());
        return;
    }

    if (ImGui::Begin("Memory")) {
        ImGui::PushFont(font_code);
        me_memory.DrawContents(buf.data(), buf.size(), addr);
        ImGui::PopFont();
    }
    ImGui::End();
}

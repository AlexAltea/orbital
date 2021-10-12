/**
 * SDL/ImGui-based user interface.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */
 
#pragma once

#include <vulkan/vulkan.h>

#define SDL_MAIN_HANDLED
#include <SDL2/SDL.h>

#include "ui/imgui/imgui_impl_sdl.h"
#include "ui/imgui/imgui_impl_vulkan.h"
#include "ui/ui_orbital.h"

// Forward declarations
class VulkanManager;
class PS4Machine;

class UI {
public:
    UI(PS4Machine& ps4);
    ~UI();

    /**
     * Main UI loop.
     */
    void task();

private:
    VulkanManager* vk;
    VkSurfaceKHR surface;
    VkDescriptorPool descriptor_pool;
    ImGui_ImplVulkanH_Window wd;

    SDL_Window* window;
    bool is_minimized;
    bool is_quitting;
    bool is_resized;
    int w;
    int h;

    // Orbital state
    OrbitalUI ui;
    PS4Machine& ps4;

    /**
     * Main UI iteration.
     */
    void loop();

    void frame_render();
    void frame_present();

    /**
     * Initialize UI backend.
     */
    static void initialize();

    /**
     * Finalize UI backend.
     */
    static void finalize();
};

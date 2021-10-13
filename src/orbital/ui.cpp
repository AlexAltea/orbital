/**
 * SDL/ImGui-based user interface.
 *
 * Copyright 2017-2020. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "ui.h"
#include <orbital/host/graphics/vulkan.h>
#include <orbital/hardware/ps4.h>

#include <SDL2/SDL_vulkan.h>

#define IMGUI_IMPL_API
#include <imgui.h>
#include "ui/imgui/imgui_impl_sdl.h"
#include "ui/imgui/imgui_impl_vulkan.h"

#include <cstdio>
#include <vector>

constexpr int ORBITAL_WIDTH = 1280;
constexpr int ORBITAL_HEIGHT = 720;

// Helpers
static void check_vk_result(VkResult err) {
    if (err == 0) {
        return;
    }
    printf("VkResult: %d\n", err);
    if (err < 0) {
        assert(0);
    }
}

UI::UI(PS4Machine& ps4) : ps4(ps4) {
    // Initial state
    is_minimized = false;
    is_quitting = false;
    is_resized = false;

    // Create SDL window
    int flags = 0;
    flags |= SDL_WINDOW_RESIZABLE;
    flags |= SDL_WINDOW_VULKAN;
    window = SDL_CreateWindow("Orbital", SDL_WINDOWPOS_UNDEFINED,
        SDL_WINDOWPOS_UNDEFINED, ORBITAL_WIDTH, ORBITAL_HEIGHT, flags);

    // Get SDL/ImGui extensions
    unsigned int count = 0;
    if (!SDL_Vulkan_GetInstanceExtensions(window, &count, nullptr)) {
        fprintf(stderr, "SDL_Vulkan_GetInstanceExtensions failed: %s\n", SDL_GetError());
        return;
    }
    std::vector<const char*> sdl_exts(count);
    if (!SDL_Vulkan_GetInstanceExtensions(window, &count, sdl_exts.data())) {
        fprintf(stderr, "SDL_Vulkan_GetInstanceExtensions failed: %s\n", SDL_GetError());
        return;
    }

    VulkanManagerConfig config = {};
    config.debug = false;// true;
    config.d_exts = {};
    config.i_exts = std::set<std::string>{
        std::make_move_iterator(sdl_exts.begin()),
        std::make_move_iterator(sdl_exts.end())};
    config.d_layers = {};
    config.i_layers = {};
    vk = new VulkanManager(config);

    // Initialize surface
    vk->init_instance(config.i_exts, config.i_layers, config.debug);
    if (!SDL_Vulkan_CreateSurface(window, vk->getInstance(), &surface)) {
        fprintf(stderr, "SDL_Vulkan_CreateSurface failed: %s\n", SDL_GetError());
        return;
    }
    vk->init_device(config.d_exts, config.d_layers, surface);
    VkInstance instance = vk->getInstance();
    VkPhysicalDevice pdev = vk->getPhysicalDevice();

    // Create framebuffers
    SDL_GetWindowSize(window, &w, &h);
    wd.Surface = surface;

    wd.ClearEnable = true;
    float clear_color[4] = {0.45f, 0.55f, 0.60f, 1.00f};
    memcpy(&wd.ClearValue.color.float32[0], &clear_color, 4 * sizeof(float));
    
    // Check for WSI support
    VkBool32 supported;
    VkResult res = vkGetPhysicalDeviceSurfaceSupportKHR(pdev, vk->getQueueFamilyIndex(), surface, &supported);
    if (res != VK_SUCCESS || supported != VK_TRUE) {
        fprintf(stderr, "Error no WSI support on physical device 0\n");
        exit(-1);
    }

    // Select Surface Format
    const VkFormat requestSurfaceImageFormat[] = {
        VK_FORMAT_B8G8R8A8_UNORM,
        VK_FORMAT_R8G8B8A8_UNORM,
        VK_FORMAT_B8G8R8_UNORM,
        VK_FORMAT_R8G8B8_UNORM
    };
    const VkColorSpaceKHR requestSurfaceColorSpace = VK_COLORSPACE_SRGB_NONLINEAR_KHR;
    wd.SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(
        pdev, surface, requestSurfaceImageFormat, IM_ARRAYSIZE(requestSurfaceImageFormat), requestSurfaceColorSpace);

    // Select Present Mode
    VkPresentModeKHR present_modes[] = {
#ifdef IMGUI_UNLIMITED_FRAME_RATE
        VK_PRESENT_MODE_MAILBOX_KHR,
        VK_PRESENT_MODE_IMMEDIATE_KHR,
        VK_PRESENT_MODE_FIFO_KHR
#else
        VK_PRESENT_MODE_FIFO_KHR
#endif
    };
    wd.PresentMode = ImGui_ImplVulkanH_SelectPresentMode(pdev, wd.Surface, present_modes, IM_ARRAYSIZE(present_modes));
    ImGui_ImplVulkanH_CreateOrResizeWindow(instance, pdev, vk->getDevice(), &wd, vk->getQueueFamilyIndex(), nullptr, w, h, 2);

    // Create Descriptor Pool
    std::vector<VkDescriptorPoolSize> pool_sizes = {
        { VK_DESCRIPTOR_TYPE_SAMPLER, 1000 },
        { VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER, 1000 },
        { VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_IMAGE, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 1000 },
        { VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC, 1000 },
        { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC, 1000 },
        { VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT, 1000 }
    };
    VkDescriptorPoolCreateInfo poolInfo = {};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    poolInfo.maxSets = 1000 * pool_sizes.size();
    poolInfo.poolSizeCount = pool_sizes.size();
    poolInfo.pPoolSizes = pool_sizes.data();
    res = vkCreateDescriptorPool(vk->getDevice(), &poolInfo, nullptr, &descriptor_pool);
    if (res != VK_SUCCESS) {
        fprintf(stderr, "vkCreateDescriptorPool failed with code: %d", res);
        return;
    }

    // Initialize ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ui.init();
    ImGui_ImplSDL2_InitForVulkan(window);

    ImGui_ImplVulkan_InitInfo init_info = {};
    init_info.Instance = vk->getInstance();
    init_info.PhysicalDevice = vk->getPhysicalDevice();
    init_info.Device = vk->getDevice();
    init_info.QueueFamily = vk->getQueueFamilyIndex();
    init_info.Queue = vk->getQueue();
    init_info.PipelineCache = VK_NULL_HANDLE;
    init_info.DescriptorPool = descriptor_pool;
    init_info.Allocator = nullptr;
    init_info.MinImageCount = 2;
    init_info.ImageCount = wd.ImageCount;
    init_info.CheckVkResultFn = check_vk_result;
    ImGui_ImplVulkan_Init(&init_info, wd.RenderPass);

    // Upload Fonts
    VkCommandPool command_pool = wd.Frames[wd.FrameIndex].CommandPool;
    VkCommandBuffer command_buffer = wd.Frames[wd.FrameIndex].CommandBuffer;

    res = vkResetCommandPool(vk->getDevice(), command_pool, 0);
    check_vk_result(res);
    VkCommandBufferBeginInfo begin_info = {};
    begin_info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    begin_info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    res = vkBeginCommandBuffer(command_buffer, &begin_info);
    check_vk_result(res);

    ImGui_ImplVulkan_CreateFontsTexture(command_buffer);

    VkSubmitInfo end_info = {};
    end_info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    end_info.commandBufferCount = 1;
    end_info.pCommandBuffers = &command_buffer;
    res = vkEndCommandBuffer(command_buffer);
    check_vk_result(res);
    res = vkQueueSubmit(vk->getQueue(), 1, &end_info, VK_NULL_HANDLE);
    check_vk_result(res);
    res = vkDeviceWaitIdle(vk->getDevice());
    check_vk_result(res);

    ImGui_ImplVulkan_DestroyFontUploadObjects();
}

UI::~UI() {
    delete vk;

    // Destroy SDL window
    SDL_DestroyWindow(window);
}

void UI::task() {
    while (!is_quitting) {
        loop();
    }
}

void UI::loop() {
    SDL_Event e;

    // Handle events
    while (SDL_PollEvent(&e)) {
        ImGui_ImplSDL2_ProcessEvent(&e);
        if (e.type == SDL_QUIT) {
            is_quitting = true;
            return;
        }
        if (e.type == SDL_WINDOWEVENT || e.window.windowID == SDL_GetWindowID(window)) {
            switch (e.window.event) {
            case SDL_WINDOWEVENT_CLOSE:
                is_quitting = true;
                return;
            case SDL_WINDOWEVENT_MINIMIZED:
                is_minimized = false;
                break;
            case SDL_WINDOWEVENT_MAXIMIZED:
                is_minimized = false;
                break;
            case SDL_WINDOWEVENT_EXPOSED:
                is_resized = true;
                break;
            case SDL_WINDOWEVENT_RESIZED:
                w = static_cast<int>(e.window.data1);
                h = static_cast<int>(e.window.data2);
                is_resized = true;
                break;
            }
        }
    }

    // Handle resizing
    if (is_resized) {
        is_resized = false;
        ImGui_ImplVulkan_SetMinImageCount(2);
        ImGui_ImplVulkanH_CreateOrResizeWindow(vk->getInstance(), vk->getPhysicalDevice(), vk->getDevice(),
            &wd, vk->getQueueFamilyIndex(), nullptr, w, h, 2);
        wd.FrameIndex = 0;
    }

    // Handle minimizations
    if (is_minimized == false) {
        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplSDL2_NewFrame(window);
        ImGui::NewFrame();

        // Window
        ui.render(ps4);

        ImGui::Render();
        frame_render();
        frame_present();
    }
}

void UI::frame_render() {
    VkResult res;
    VkDevice dev = vk->getDevice();
    VkSemaphore image_acquired_semaphore  = wd.FrameSemaphores[wd.SemaphoreIndex].ImageAcquiredSemaphore;
    VkSemaphore render_complete_semaphore = wd.FrameSemaphores[wd.SemaphoreIndex].RenderCompleteSemaphore;
    res = vkAcquireNextImageKHR(dev, wd.Swapchain, UINT64_MAX, image_acquired_semaphore, VK_NULL_HANDLE, &wd.FrameIndex);
    check_vk_result(res);

    ImGui_ImplVulkanH_Frame& fd = wd.Frames[wd.FrameIndex];

    // Wait indefinitely instead of periodically checking
    res = vkWaitForFences(dev, 1, &fd.Fence, VK_TRUE, UINT64_MAX);
    check_vk_result(res);

    res = vkResetFences(dev, 1, &fd.Fence);
    check_vk_result(res);

    res = vkResetCommandPool(dev, fd.CommandPool, 0);
    check_vk_result(res);
    {
        VkCommandBufferBeginInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        info.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        res = vkBeginCommandBuffer(fd.CommandBuffer, &info);
        check_vk_result(res);
    }
    {
        VkRenderPassBeginInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
        info.renderPass = wd.RenderPass;
        info.framebuffer = fd.Framebuffer;
        info.renderArea.extent.width = wd.Width;
        info.renderArea.extent.height = wd.Height;
        info.clearValueCount = 1;
        info.pClearValues = &wd.ClearValue;
        vkCmdBeginRenderPass(fd.CommandBuffer, &info, VK_SUBPASS_CONTENTS_INLINE);
    }

    // Record Imgui Draw Data and draw funcs into command buffer
    ImGui_ImplVulkan_RenderDrawData(ImGui::GetDrawData(), fd.CommandBuffer);

    // Submit command buffer
    vkCmdEndRenderPass(fd.CommandBuffer);
    {
        VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
        VkSubmitInfo info = {};
        info.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        info.waitSemaphoreCount = 1;
        info.pWaitSemaphores = &image_acquired_semaphore;
        info.pWaitDstStageMask = &wait_stage;
        info.commandBufferCount = 1;
        info.pCommandBuffers = &fd.CommandBuffer;
        info.signalSemaphoreCount = 1;
        info.pSignalSemaphores = &render_complete_semaphore;

        res = vkEndCommandBuffer(fd.CommandBuffer);
        check_vk_result(res);
        res = vkQueueSubmit(vk->getQueue(), 1, &info, fd.Fence);
        check_vk_result(res);
    }
}

void UI::frame_present() {
    std::vector<VkSemaphore> waitSemaphores = {
        wd.FrameSemaphores[wd.SemaphoreIndex].RenderCompleteSemaphore
    };

    VkPresentInfoKHR info = {};
    info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    info.waitSemaphoreCount = waitSemaphores.size();
    info.pWaitSemaphores = waitSemaphores.data();
    info.swapchainCount = 1;
    info.pSwapchains = &wd.Swapchain;
    info.pImageIndices = &wd.FrameIndex;
    VkResult res = vkQueuePresentKHR(vk->getQueue(), &info);
    if (res == VK_ERROR_OUT_OF_DATE_KHR || res == VK_SUBOPTIMAL_KHR) {
        is_resized = true;
        return;
    }

    // Now we can use the next set of semaphores
    wd.SemaphoreIndex = (wd.SemaphoreIndex + 1) % wd.ImageCount;
}

void UI::initialize() {
    static bool initialized = false;
    if (initialized) {
        return;
    }

    // Initialize SDL library
    SDL_SetMainReady();

    // Initialize SDL subsystems
    int err = SDL_InitSubSystem(SDL_INIT_VIDEO);
    if (err) {
        fprintf(stderr, "SDL_InitSubSystem failed: %s\n", SDL_GetError());
        return;
    }

    initialized = true;
}

void UI::finalize() {
    // Finalize SDL library
    SDL_Quit();
}

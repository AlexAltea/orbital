/**
 * Vulkan graphics backend.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <vulkan/vulkan.h>

#include <set>
#include <string>
#include <vector>

enum VulkanManagerMode {
    VULKAN_MANAGER_CREATE,
    VULKAN_MANAGER_REUSE,
};

struct VulkanManagerConfig {
    // Reusing
    VkInstance instance = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;

    // Creating
    bool debug;
    std::set<std::string> i_exts;
    std::set<std::string> i_layers;
    std::set<std::string> d_exts;
    std::set<std::string> d_layers;
};

class VulkanManager {
public:
    VulkanManager(const VulkanManagerConfig& config = {});
    ~VulkanManager();

    VkInstance getInstance() const {
        return instance;
    }
    VkPhysicalDevice getPhysicalDevice() const {
        return pdev;
    }
    VkDevice getDevice() const {
        return device;
    }
    uint32_t getQueueFamilyIndex() const {
        return queueFamilyIndex;
    }
    VkQueue getQueue() const {
        return queue;
    }

    /**
     * Create Vulkan instance.
     */
    void init_instance(std::set<std::string> exts, std::set<std::string> layers, bool debug);

    /**
     * Create Vulkan device.
     */
    void init_device(std::set<std::string> exts, std::set<std::string> layers, VkSurfaceKHR surface);

private:
    VkInstance instance;
    VkDebugUtilsMessengerEXT debug_messenger;

    VkPhysicalDevice pdev;
    VkDevice device;
    uint32_t queueFamilyIndex;
    VkQueue queue;

    // Helpers

    /**
     * Find suitable queue for graphics commands.
     */
    uint32_t find_queue_graphics(const std::vector<VkQueueFamilyProperties>& qprops, VkSurfaceKHR surface);
};

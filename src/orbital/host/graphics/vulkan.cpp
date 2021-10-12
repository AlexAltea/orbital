/**
 * Vulkan graphics backend.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "vulkan.h"

#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <string_view>

// Helpers
static VKAPI_ATTR VkBool32 VKAPI_CALL debugCallback(
    VkDebugUtilsMessageSeverityFlagBitsEXT messageSeverity,
    VkDebugUtilsMessageTypeFlagsEXT messageType,
    const VkDebugUtilsMessengerCallbackDataEXT* pCallbackData, void* pUserData) {
    // Get underlying manager
    auto manager = static_cast<VulkanManager*>(pUserData);
    fprintf(stderr, "Validation Layer: %s\n", pCallbackData->pMessage);
    return VK_FALSE;
}

// Extensions
static VkResult CreateDebugUtilsMessengerEXT(VkInstance instance,
    const VkDebugUtilsMessengerCreateInfoEXT* pCreateInfo,
    const VkAllocationCallbacks* pAllocator,
    VkDebugUtilsMessengerEXT* pDebugMessenger) {
    // Get function address
    auto func = vkGetInstanceProcAddr(instance, "vkCreateDebugUtilsMessengerEXT");
    if (func) {
        return reinterpret_cast<PFN_vkCreateDebugUtilsMessengerEXT>(func)(
            instance, pCreateInfo, pAllocator, pDebugMessenger);
    }
    return VK_ERROR_EXTENSION_NOT_PRESENT;
}

bool check_validation_layers(const std::set<std::string>& requestedNames) {
    VkResult res;
    
    uint32_t availableLayerCount = 0;
    res = vkEnumerateInstanceLayerProperties(&availableLayerCount, nullptr);
    assert(res == VK_SUCCESS);

    std::vector<VkLayerProperties> availableLayers(availableLayerCount);
    res = vkEnumerateInstanceLayerProperties(&availableLayerCount, availableLayers.data());
    assert(res == VK_SUCCESS);

    for (const auto& requestedName : requestedNames) {
        bool layerFound = false;
        for (const auto& availableLayer : availableLayers) {
            if (availableLayer.layerName == requestedName) {
                layerFound = true;
                break;
            }
        }
        if (!layerFound) {
            return false;
        }
    }
    return true;
}

VulkanManager::VulkanManager(const VulkanManagerConfig& config)
    : instance(config.instance), device(config.device) {
}

VulkanManager::~VulkanManager() {
}

void VulkanManager::init_instance(std::set<std::string> exts, std::set<std::string> layers, bool debug) {
    // Determine the actual number of layers/extensions
    if (debug) {
        exts.insert(VK_EXT_DEBUG_UTILS_EXTENSION_NAME);
        layers.insert("VK_LAYER_KHRONOS_validation");
    }
    check_validation_layers(layers);

    // Prepare name arrays
    std::vector<const char*> name_exts;
    std::vector<const char*> name_layers;
    for (const auto& s : exts) {
        name_exts.push_back(s.c_str());
    }
    for (const auto& s : layers) {
        name_layers.push_back(s.c_str());
    }

    VkApplicationInfo applicationInfo = {};
    applicationInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    applicationInfo.pNext = nullptr;
    applicationInfo.pApplicationName = "Orbital";
    applicationInfo.applicationVersion = 1;
    applicationInfo.pEngineName = "orbital-vk";
    applicationInfo.engineVersion = 1;
    applicationInfo.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo instanceInfo = {};
    instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    instanceInfo.pNext = nullptr;
    instanceInfo.flags = 0;
    instanceInfo.pApplicationInfo = &applicationInfo;
    instanceInfo.enabledLayerCount = name_layers.size();
    instanceInfo.ppEnabledLayerNames = name_layers.data();
    instanceInfo.enabledExtensionCount = name_exts.size();
    instanceInfo.ppEnabledExtensionNames = name_exts.data();

    VkResult res = vkCreateInstance(&instanceInfo, nullptr, &instance);
    if (res != VK_SUCCESS) {
        fprintf(stderr, "vkCreateInstance failed with code: %d\n", res);
        return;
    }

    // Setup debugging
    if (debug) {
        VkDebugUtilsMessengerCreateInfoEXT createInfo = {};
        createInfo.sType = VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT;
        createInfo.messageSeverity =
            VK_DEBUG_UTILS_MESSAGE_SEVERITY_VERBOSE_BIT_EXT |
            VK_DEBUG_UTILS_MESSAGE_SEVERITY_WARNING_BIT_EXT |
            VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT;
        createInfo.messageType =
            VK_DEBUG_UTILS_MESSAGE_TYPE_GENERAL_BIT_EXT |
            VK_DEBUG_UTILS_MESSAGE_TYPE_VALIDATION_BIT_EXT |
            VK_DEBUG_UTILS_MESSAGE_TYPE_PERFORMANCE_BIT_EXT;
        createInfo.pfnUserCallback = debugCallback;
        createInfo.pUserData = this;

        res = CreateDebugUtilsMessengerEXT(instance, &createInfo, nullptr, &debug_messenger);
        if (res != VK_SUCCESS) {
            fprintf(stderr, "vkCreateDebugUtilsMessengerEXT failed with code: %d\n", res);
            return;
        }
    }
}

void VulkanManager::init_device(std::set<std::string> exts, std::set<std::string> layers, VkSurfaceKHR surface) {
    VkResult res;

    exts.insert(VK_KHR_SWAPCHAIN_EXTENSION_NAME);

    // Prepare name arrays
    std::vector<const char*> name_exts;
    std::vector<const char*> name_layers;
    for (const auto& s : exts) {
        name_exts.push_back(s.c_str());
    }
    for (const auto& s : layers) {
        name_layers.push_back(s.c_str());
    }

    // Get physical device
    uint32_t pdevs_count;
    res = vkEnumeratePhysicalDevices(instance, &pdevs_count, nullptr);
    if (res != VK_SUCCESS) {
        fprintf(stderr, "vkEnumeratePhysicalDevices failed with code: %d", res);
        return;
    }
    assert(pdevs_count >= 1);
    std::vector<VkPhysicalDevice> pdevs(pdevs_count);
    res = vkEnumeratePhysicalDevices(instance, &pdevs_count, pdevs.data());
    if (res != VK_SUCCESS) {
        fprintf(stderr, "vkEnumeratePhysicalDevices failed with code: %d", res);
        return;
    }

    pdev = pdevs[0];
    VkPhysicalDeviceFeatures pdev_features;
    VkPhysicalDeviceProperties pdev_props;
    VkPhysicalDeviceMemoryProperties pdev_mprops;
    vkGetPhysicalDeviceFeatures(pdev, &pdev_features);
    vkGetPhysicalDeviceProperties(pdev, &pdev_props);
    vkGetPhysicalDeviceMemoryProperties(pdev, &pdev_mprops);

    // Get graphics queue
    uint32_t qprops_count;
    vkGetPhysicalDeviceQueueFamilyProperties(pdev, &qprops_count, nullptr);
    assert(qprops_count >= 1);
    std::vector<VkQueueFamilyProperties> qprops(qprops_count);
    vkGetPhysicalDeviceQueueFamilyProperties(pdev, &qprops_count, qprops.data());

    queueFamilyIndex = find_queue_graphics(qprops, surface);
    float queue_priorities[1] = { 0.0 };

    VkDeviceQueueCreateInfo deviceQueue = {};
    deviceQueue.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    deviceQueue.pNext = nullptr;
    deviceQueue.queueFamilyIndex = queueFamilyIndex;
    deviceQueue.queueCount = 1;
    deviceQueue.pQueuePriorities = queue_priorities;

    VkDeviceCreateInfo deviceInfo = {};
    deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    deviceInfo.pNext = nullptr;
    deviceInfo.queueCreateInfoCount = 1;
    deviceInfo.pQueueCreateInfos = &deviceQueue;
    deviceInfo.pEnabledFeatures = nullptr;
    deviceInfo.enabledExtensionCount = name_exts.size();
    deviceInfo.ppEnabledExtensionNames = name_exts.data();
    deviceInfo.enabledLayerCount = name_layers.size();
    deviceInfo.ppEnabledLayerNames = name_layers.data();
    res = vkCreateDevice(pdev, &deviceInfo, nullptr, &device);
    if (res != VK_SUCCESS) {
        fprintf(stderr, "vkCreateInstance failed with code: %d\n", res);
        return;
    }
    
    // Get queue
    vkGetDeviceQueue(device, queueFamilyIndex, 0, &queue);
}

uint32_t VulkanManager::find_queue_graphics(const std::vector<VkQueueFamilyProperties>& qprops, VkSurfaceKHR surface) {
    uint32_t graphicsQueueNodeIndex = UINT32_MAX;
    uint32_t presentQueueNodeIndex = UINT32_MAX;

    for (uint32_t i = 0; i < qprops.size(); i++) {
        if (qprops[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) {
            VkBool32 supportsPresent;
            vkGetPhysicalDeviceSurfaceSupportKHR(pdev, i, surface, &supportsPresent);
            if (graphicsQueueNodeIndex == UINT32_MAX) {
                graphicsQueueNodeIndex = i;
            }
            if (supportsPresent == VK_TRUE) {
                graphicsQueueNodeIndex = i;
                presentQueueNodeIndex = i;
                break;
            }
        }
    }
    if (presentQueueNodeIndex == UINT32_MAX) {
        for (uint32_t i = 0; i < qprops.size(); i++) {
            VkBool32 supportsPresent;
            vkGetPhysicalDeviceSurfaceSupportKHR(pdev, i, surface, &supportsPresent);
            if (supportsPresent == VK_TRUE) {
                presentQueueNodeIndex = i;
                break;
            }
        }
    }
    if (graphicsQueueNodeIndex == UINT32_MAX || presentQueueNodeIndex == UINT32_MAX) {
        fprintf(stderr, "vk_init_device: Could not find a graphics and a present queue\n");
        return UINT32_MAX;
    }
    if (graphicsQueueNodeIndex != presentQueueNodeIndex) {
        fprintf(stderr, "vk_init_device: Could not find a common graphics and a present queue\n");
        return UINT32_MAX;
    }
    return graphicsQueueNodeIndex;
}

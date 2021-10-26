/**
 * Liverpool North Bridge (NB) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "liverpool_nb.h"

LiverpoolNBFnc0Device::LiverpoolNBFnc0Device(PCIBus* bus, const LiverpoolNBFnc0DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc0Device::~LiverpoolNBFnc0Device() {
}

void LiverpoolNBFnc0Device::reset() {
}

LiverpoolNBFnc1Device::LiverpoolNBFnc1Device(PCIBus* bus, const LiverpoolNBFnc1DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc1Device::~LiverpoolNBFnc1Device() {
}

void LiverpoolNBFnc1Device::reset() {
}

LiverpoolNBFnc2Device::LiverpoolNBFnc2Device(PCIBus* bus, const LiverpoolNBFnc2DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc2Device::~LiverpoolNBFnc2Device() {
}

void LiverpoolNBFnc2Device::reset() {
}

LiverpoolNBFnc3Device::LiverpoolNBFnc3Device(PCIBus* bus, const LiverpoolNBFnc3DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc3Device::~LiverpoolNBFnc3Device() {
}

void LiverpoolNBFnc3Device::reset() {
    /**
     * Set APU chipset version.
     * Liverpool:
     * - 0x00710F00 : LVP A0
     * - 0x00710F10 : LVP B0
     * - 0x00710F11 : LVP B1
     * - 0x00710F12 : LVP B2
     * - 0x00710F13 : LVP B2.1
     * - 0x00710F30 : LVP+ A0
     * - 0x00710F31 : LVP+ A0b
     * - 0x00710F32 : LVP+ A1
     * - 0x00710F40 : LVP+ B0
     * - 0x00710F80 : LVP2 A0
     * - 0x00710F81 : LVP2 A1
     * - 0x00710FA0 : LVP2C A0
     * Gladius:
     * - 0x00740F00 : GL A0
     * - 0x00740F01 : GL A1
     * - 0x00740F10 : GL B0
     * - 0x00740F11 : GL B1
     * - 0x00740F12 : GL T(B2)
     */
    constexpr U32 REG_NB_CPUID_3XFC = 0xFC;
    (U32&)config_data[REG_NB_CPUID_3XFC] = 0x00710F13;
}

LiverpoolNBFnc4Device::LiverpoolNBFnc4Device(PCIBus* bus, const LiverpoolNBFnc4DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc4Device::~LiverpoolNBFnc4Device() {
}

void LiverpoolNBFnc4Device::reset() {
}

LiverpoolNBFnc5Device::LiverpoolNBFnc5Device(PCIBus* bus, const LiverpoolNBFnc5DeviceConfig& config)
    : PCIDevice(bus, config) {
    reset();
}

LiverpoolNBFnc5Device::~LiverpoolNBFnc5Device() {
}

void LiverpoolNBFnc5Device::reset() {
}

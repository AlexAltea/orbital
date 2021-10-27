/**
 * Liverpool North Bridge (NB) PCI device.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

enum {
    LIVERPOOL_NB_DEV = 0x18,
    LIVERPOOL_NB_FNC0 = 0,
    LIVERPOOL_NB_FNC1 = 1,
    LIVERPOOL_NB_FNC2 = 2,
    LIVERPOOL_NB_FNC3 = 3,
    LIVERPOOL_NB_FNC4 = 4,
    LIVERPOOL_NB_FNC5 = 5,
};

constexpr auto LIVERPOOL_NB_FNC0_DID = static_cast<PCIDeviceId>(0x142E);
constexpr auto LIVERPOOL_NB_FNC1_DID = static_cast<PCIDeviceId>(0x142F);
constexpr auto LIVERPOOL_NB_FNC2_DID = static_cast<PCIDeviceId>(0x1430);
constexpr auto LIVERPOOL_NB_FNC3_DID = static_cast<PCIDeviceId>(0x1431);
constexpr auto LIVERPOOL_NB_FNC4_DID = static_cast<PCIDeviceId>(0x1432);
constexpr auto LIVERPOOL_NB_FNC5_DID = static_cast<PCIDeviceId>(0x1433);

struct LiverpoolNBFnc0DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc0DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC0))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC0_DID, 0x1, 0x0) {
    }
};

struct LiverpoolNBFnc1DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc1DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC1))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC1_DID, 0x1, 0x0) {
    }
};

struct LiverpoolNBFnc2DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc2DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC2))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC2_DID, 0x1, 0x0) {
    }
};

struct LiverpoolNBFnc3DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc3DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC3))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC3_DID, 0x1, 0x0) {
    }
};

struct LiverpoolNBFnc4DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc4DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC4))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC4_DID, 0x1, 0x0) {
    }
};

struct LiverpoolNBFnc5DeviceConfig : PCIeDeviceConfig {
    LiverpoolNBFnc5DeviceConfig(PCI_DF df = PCI_DF(LIVERPOOL_NB_DEV, LIVERPOOL_NB_FNC5))
        : PCIeDeviceConfig(df, PCI_VENDOR_ID_AMD, LIVERPOOL_NB_FNC5_DID, 0x1, 0x0) {
    }
};

class LiverpoolNBFnc0Device final : public PCIeDevice {
public:
    LiverpoolNBFnc0Device(PCIeBus* bus, const LiverpoolNBFnc0DeviceConfig& config = {});
    ~LiverpoolNBFnc0Device();

    // Device interface
    void reset() override;
};

class LiverpoolNBFnc1Device final : public PCIeDevice {
public:
    LiverpoolNBFnc1Device(PCIeBus* bus, const LiverpoolNBFnc1DeviceConfig& config = {});
    ~LiverpoolNBFnc1Device();

    // Device interface
    void reset() override;
};

class LiverpoolNBFnc2Device final : public PCIeDevice {
public:
    LiverpoolNBFnc2Device(PCIeBus* bus, const LiverpoolNBFnc2DeviceConfig& config = {});
    ~LiverpoolNBFnc2Device();

    // Device interface
    void reset() override;
};

class LiverpoolNBFnc3Device final : public PCIeDevice {
public:
    LiverpoolNBFnc3Device(PCIeBus* bus, const LiverpoolNBFnc3DeviceConfig& config = {});
    ~LiverpoolNBFnc3Device();

    // Device interface
    void reset() override;
};

class LiverpoolNBFnc4Device final : public PCIeDevice {
public:
    LiverpoolNBFnc4Device(PCIeBus* bus, const LiverpoolNBFnc4DeviceConfig& config = {});
    ~LiverpoolNBFnc4Device();

    // Device interface
    void reset() override;
};

class LiverpoolNBFnc5Device final : public PCIeDevice {
public:
    LiverpoolNBFnc5Device(PCIeBus* bus, const LiverpoolNBFnc5DeviceConfig& config = {});
    ~LiverpoolNBFnc5Device();

    // Device interface
    void reset() override;
};

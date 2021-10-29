/**
 * ImguiCharHost.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#pragma once

#include <orbital/core.h>

// Forward declarations
class ToolLogs;

struct ImguiCharHostConfig {
    ToolLogs* logs = nullptr;
};

class ImguiCharHost final : public CharHost {
public:
    ImguiCharHost(Object* parent = nullptr, const ImguiCharHostConfig& config = {});
    ~ImguiCharHost();

    U32 get_features() const override;
    std::vector<U8> read(size_t max_read) override;
    size_t write(const std::vector<U8>& data) override;
    size_t read_data_avail() override {
        return 0;
    }

private:
    ToolLogs* logs;
};

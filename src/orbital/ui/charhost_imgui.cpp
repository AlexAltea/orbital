/**
 * ImguiCharHost.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "charhost_imgui.h"
#include "tool_logs.h"

ImguiCharHost::ImguiCharHost(Object* parent, const ImguiCharHostConfig& config)
    : CharHost(parent), logs(config.logs) {
}

ImguiCharHost::~ImguiCharHost() {
}

U32 ImguiCharHost::get_features() const {
    return CH_FEAT_WRITE;
}

std::vector<U8> ImguiCharHost::read(size_t max_read) {
    assert_always("Unimplemented");
    return {};
}

size_t ImguiCharHost::write(const std::vector<U8>& data) {
    size_t count = 0;
    for (const auto& c : data) {
        logs->Log(c);
    }
    return count;
}

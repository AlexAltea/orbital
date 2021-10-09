/**
 * PS4 cryptography.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "crypto.h"

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

#include <fstream>
#include <stdexcept>

static Crypto g_ps4Crypto;

static Key parseAesKey(Key::Type type, const rapidjson::Value& value) {
    auto key = value["aes_key"].GetString();
    auto iv  = value["aes_iv"].GetString();
    return Key(type, key, iv);
}

const Crypto& ps4Crypto() {
    if (g_ps4Crypto.size() > 0) {
        return g_ps4Crypto;
    }

    // Parse keys from hardcoded file
    std::ifstream ifs("crypto/keys.json");
    rapidjson::IStreamWrapper isw(ifs);
    rapidjson::Document document;
    document.ParseStream(isw);

    // Add individual keys
    g_ps4Crypto.add("pup.hdr",
        parseAesKey(Key::AES_128_CBC, document["pup"]["hdr"]));
    g_ps4Crypto.add("pup.root_key",
        parseAesKey(Key::AES_128_CBC, document["pup"]["root_key"]));

    for (const auto& m : document["self"]["80010002"].GetObject()) {
        std::string name = "self.80010002.";
        g_ps4Crypto.add(name + m.name.GetString(), parseAesKey(Key::AES_128_CBC, m.value));
    }

    return g_ps4Crypto;
}

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

static uint8_t parseHex(char input) {
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

static void parseHexBytes(std::string_view hex, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < hex.size() && i < 2*len; i += 2) {
        buf[i >> 1] = parseHex(hex[i]) * 16 + parseHex(hex[i + 1]);
    }
}

static Key parseAesKey(Key::Type type, const rapidjson::Value& value) {
    Key k = { type };
    parseHexBytes(value["aes_key"].GetString(),
        k.aes.key, sizeof(k.aes.key));
    parseHexBytes(value["aes_iv"].GetString(),
        k.aes.iv, sizeof(k.aes.iv));
    return k;
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

    return g_ps4Crypto;
}

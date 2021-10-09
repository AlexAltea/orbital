/**
 * Cryptography.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */
 
#pragma once

#include <core.h>

#include <botan/botan.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>

struct Key {
    enum Type {
        NONE,
        AES_128_EBC,
        AES_128_CBC,
    } type;

    Botan::SymmetricKey key;
    Botan::InitializationVector iv;

    Key() : type(NONE) {}
    Key(Type type, const void* key_buf, size_t key_len, const void* iv_buf, size_t iv_len)
        : type(type), key((const U8*)key_buf, key_len), iv((const U8*)iv_buf, iv_len) {
    }
    Key(Type type, std::string_view key, std::string_view iv)
        : type(type), key(std::string(key)), iv(std::string(iv)) {
    }
};

class CryptoStream : public Stream {
    Stream& s;
    Key key;

public:
    CryptoStream(Stream& s, const Key& key) : s(s), key(key) {}

    // Interface
    virtual U64 read(U64 size, void* buffer) override;
    virtual U64 write(U64 size, const void* buffer) override;
    virtual void seek(U64 offset, StreamSeek mode) override;
    virtual U64 tell() const override;
};

class CryptoVault {
    std::map<std::string, Key> keys;

public:
    /**
     * Add named key to the vault.
     * @param[in]  name  Unique key identifier
     * @param[in]  key   Key data
     */
    void add(std::string_view name, Key key) {
        std::string k(name);
        keys[k] = key;
    }

    /**
     * Get key by name.
     * @param[in]  name  Unique key identifier
     */
    const Key& get(std::string_view name) const {
        std::string k(name);
        return keys.at(k);
    }

    /**
     * Remove key by name.
     * @param[in]  name  Unique key identifier
     */
    void remove(std::string_view name) {
        std::string k(name);
        keys.erase(k);
    }

    /**
     * Number of keys in the vault.
     */
    size_t size() const {
        return keys.size();
    }
};

class Crypto : public CryptoVault {
public:
    /**
     * Decrypt typed data with specified key.
     * @tparam     T      Type of the data to decrypt
     * @param[in]  value  Typed value to decrypt
     * @param[in]  key    Unique identifier of key in vault
     */
    template <typename T>
    T decrypt(const T& value, std::string_view key) const {
        return decrypt<T>(value, get(key));
    }

    /**
     * Read and decrypt typed data with specified key.
     * @tparam     T      Type of the data to decrypt
     * @param[in]  s      Stream to read encrypted typed data from
     * @param[in]  key    Unique identifier of key in vault
     */
    template <typename T>
    T decrypt(Stream& s, std::string_view key) const {
        return decrypt<T>(s, get(key));
    }

    // Static methods

    /**
     * Decrypt typed data with specified key.
     */
    template <typename T>
    static T decrypt(const T& value, Key key) {
        T output = {};
        decrypt(&value, sizeof(T), &output, sizeof(T), key);
        return output;
    }

    /**
     * Read and decrypt typed data with specified key.
     */
    template <typename T>
    static T decrypt(Stream& s, Key key) {
        T output = s.read_t<T>();
        decrypt(&output, sizeof(T), key);
        return output;
    }

    /**
     * Decrypt buffer in-place with specified key.
     * @param[in,out]  buf  Pointer to input/output data
     * @param[in,out]  len  Input/Output length in bytes
     * @param[in]      key  Decryption key
     */
    static void decrypt(void* buf, size_t len, Key key);

    /**
     * Decrypt buffer with specified key.
     * @param[in]   input_buf   Pointer to input data
     * @param[in]   input_len   Input length in bytes
     * @param[out]  output_buf  Pointer to output data
     * @param[out]  output_len  Output length in bytes
     * @param[in]   key         Decryption key
     */
    static void decrypt(const void* input_buf, size_t input_len,
        void* output_buf, size_t output_len, Key key);

    /**
     * Decrypt buffer with specified key.
     */
    static Buffer decrypt(const Buffer& buffer, Key key);

    /**
     * Decrypt stream with specified key.
     */
    static CryptoStream decrypt(Stream& s, Key key);
};

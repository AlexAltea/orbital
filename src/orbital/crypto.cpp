/**
 * Cryptography.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "crypto.h"

// Global
Crypto crypto;

U64 CryptoStream::read(U64 size, void* buffer) {
    return 0;
}

U64 CryptoStream::write(U64 size, const void* buffer) {
    return 0;
}

void CryptoStream::seek(U64 offset, StreamSeek mode) {
    s.seek(offset, mode);
}

U64 CryptoStream::tell() const {
    return s.tell();
}

void Crypto::decrypt(void* buf, size_t len, Key key) {
    Crypto::decrypt(buf, len, buf, len, key);
}

void Crypto::decrypt(const void* input_buf, size_t input_len,
    void* output_buf, size_t output_len, Key key) {
    // TODO
}

Buffer Crypto::decrypt(const Buffer& buffer, Key key) {
    Buffer output(buffer.size());
    decrypt(buffer.data(), buffer.size(), output.data(), output.size(), key);
    return output;
}

CryptoStream Crypto::decrypt(Stream& s, Key key) {
    return CryptoStream(s, key);
}

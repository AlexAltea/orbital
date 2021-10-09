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

#include <stdexcept>

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
    const char* algo;
    switch (key.type) {
    case Key::AES_128_EBC:
        algo = "AES-128/EBC";
        break;
    case Key::AES_128_CBC:
        algo = "AES-128/CBC/CTS";
        break;
    default:
        throw std::invalid_argument("Unrecognized key type");
    }
    auto cipher = Botan::get_cipher(algo, key.key, key.iv, Botan::Cipher_Dir::DECRYPTION);
    Botan::Pipe pipe(cipher);
    pipe.start_msg();
    pipe.write((const uint8_t*)input_buf, input_len);
    pipe.end_msg();
    pipe.read((uint8_t*)output_buf, output_len);
}

Buffer Crypto::decrypt(const Buffer& buffer, Key key) {
    Buffer output(buffer.size());
    decrypt(buffer.data(), buffer.size(), output.data(), output.size(), key);
    return output;
}

CryptoStream Crypto::decrypt(Stream& s, Key key) {
    return CryptoStream(s, key);
}

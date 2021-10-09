/**
 * Common Format (CF) format.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include "cf.h"

#include <botan/botan.h>

void CfParser::decrypt(Buffer& buffer, const CfMeta& meta) {
    Botan::SymmetricKey key(meta.data_key, 16);
    Botan::InitializationVector iv(meta.data_iv, 16);
    auto cipher = Botan::get_cipher("AES-128/CBC/NoPadding", key, iv, Botan::Cipher_Dir::DECRYPTION);

    const auto size_aligned = buffer.size() & ~0xF;
    const auto overflow = buffer.size() & 0xF;
    U08 prev_block[16];
    U08 next_block[16];
    if (overflow && size_aligned >= 16) {
        memcpy(prev_block, &buffer[size_aligned - 16], 16);
    }

    Botan::Pipe pipe(cipher);
    pipe.start_msg();
    pipe.write(buffer.data(), size_aligned);
    pipe.end_msg();
    pipe.read(buffer.data(), size_aligned);

    // Apply custom CTS if unaligned
    if (overflow) {
        auto cipher_enc = Botan::get_cipher("AES-128/CBC", key, Botan::Cipher_Dir::ENCRYPTION);
        Botan::Pipe pipe_enc(cipher_enc);
        pipe_enc.start_msg();
        pipe_enc.write(prev_block, 16);
        pipe_enc.end_msg();
        pipe_enc.read(next_block, 16);
        for (size_t i = 0; i < overflow; i++) {
            buffer[size_aligned + i] ^= next_block[i];
        }
    }
}

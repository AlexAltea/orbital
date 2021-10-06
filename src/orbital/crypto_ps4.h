/**
 * PS4 cryptography.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */
 
#pragma once

#include <orbital/crypto.h>

 /**
  * Returns the global Crypto object that stores/uses PS4 keys.
  * Ideally, keys should be hardcoded in the hardware/software emulators.
  * However for legal reasons we are not allowed to ship cryptographic keys,
  * hence this annoying layer of abstraction.
  */
const Crypto& ps4Crypto();

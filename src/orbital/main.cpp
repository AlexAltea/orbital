/**
 * Orbital entry point.
 *
 * Copyright 2017-2021. Orbital project.
 * Released under MIT license. Read LICENSE for more details.
 *
 * Authors:
 * - Alexandro Sanchez Bach <alexandro@phi.nz>
 */

#include <orbital/hardware/ps4.h>
#include <orbital/ui.h>

#include <stdio.h>

int main(int argc, char** argv) {
    PS4MachineConfig config = {};

    PS4Machine ps4(config);
    ps4.recover("pups/PS4UPDATE.PUP");
    ps4.resume();

    UI ui(ps4);

    ui.task();
    return 0;
}

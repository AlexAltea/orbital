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
    UI ui{};

    PS4MachineConfig config = {};
    config.aeolia_uart0 = ui.get_uart0_backend();
    config.aeolia_uart1 = ui.get_uart1_backend();

    PS4Machine ps4(config);
    ps4.recover("pups/PS4UPDATE.PUP");
    ps4.resume();


    ui.task(ps4);
    return 0;
}

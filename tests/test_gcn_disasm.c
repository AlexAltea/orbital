/**
 * (c) 2019 Alexandro Sanchez Bach. All rights reserved.
 * Released under MIT license. Read LICENSE for more details.
 */

#include "gcn_disasm.h"
#include "gcn_parser.h"

#include <stdio.h>

static int disasm_shader(const uint8_t *data, size_t size)
{
    gcn_parser_t parser;
    gcn_disasm_t disasm;

    gcn_parser_init(&parser);
    gcn_disasm_init(&disasm);
    gcn_parser_parse(&parser, data, &gcn_disasm_callbacks, &disasm);
    return 0;
}

int main(int argc, const char **argv)
{
    size_t shader_size;
    uint8_t *shader_data;
    const char *name;
    FILE *file;
    int ret;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s [path/to/shader.bin]\n", argv[0]);
        return 0;
    }

    name = argv[1];
    file = fopen(name, "rb");
    if (!file) {
        fprintf(stderr, "File %s does not exist!\n", name);
        return 1;
    }
    fseek(file, 0, SEEK_END);
    shader_size = ftell(file);
    shader_data = malloc(shader_size);
    if (!shader_data) {
        fprintf(stderr, "Could not allocate 0x%zX bytes!\n", shader_size);
        return 1;
    }
    fseek(file, 0, SEEK_SET);
    fread(shader_data, 1, shader_size, file);
    ret = disasm_shader(shader_data, shader_size);
    free(shader_data);
    fclose(file);

    return ret;
}

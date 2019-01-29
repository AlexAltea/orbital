/**
 * (c) 2019 Alexandro Sanchez Bach. All rights reserved.
 * Released under MIT license. Read LICENSE for more details.
 */

#include "gcn_analyzer.h"
#include "gcn_translator.h"
#include "gcn_parser.h"

#include <cstdio>
#include <cstdlib>
#include <vector>

#define UNUSED(arg) (void)(arg)

static int translate_shader(const uint8_t *data, size_t size, const char *stage)
{
    UNUSED(size);
    gcn_parser_t parser;
    gcn_analyzer_t analyzer;
    gcn_translator_t *translator = NULL;
    uint8_t *bc_data;
    uint32_t bc_size;

    gcn_parser_init(&parser);
    gcn_analyzer_init(&analyzer);
    gcn_parser_parse(&parser, data, &gcn_analyzer_callbacks, &analyzer);

    if (!strcmp(stage, "ps"))
        translator = gcn_translator_create(&analyzer, GCN_STAGE_PS);
    if (!strcmp(stage, "vs"))
        translator = gcn_translator_create(&analyzer, GCN_STAGE_VS);
    if (!translator)
        return 1;

    gcn_parser_init(&parser);
    gcn_parser_parse(&parser, data, &gcn_translator_callbacks, translator);
    bc_data = gcn_translator_dump(translator, &bc_size);

    fwrite(bc_data, 1, bc_size, stdout);
    return 0;
}

int main(int argc, const char **argv)
{
    size_t shader_size;
    uint8_t *shader_data;
    const char *name, *stage;
    FILE *file;
    int ret;

    if (argc <= 2) {
        fprintf(stderr, "Usage: %s {ps,vs} [path/to/shader.bin]\n", argv[0]);
        return 0;
    }

    stage = argv[1];
    name = argv[2];
    file = fopen(name, "rb");
    if (!file) {
        fprintf(stderr, "File %s does not exist!\n", name);
        return 1;
    }
    fseek(file, 0, SEEK_END);
    shader_size = ftell(file);
    shader_data = reinterpret_cast<uint8_t*>(malloc(shader_size));
    if (!shader_data) {
        fprintf(stderr, "Could not allocate 0x%zX bytes!\n", shader_size);
        return 1;
    }
    fseek(file, 0, SEEK_SET);
    if (fread(shader_data, 1, shader_size, file) != shader_size) {
        fprintf(stderr, "Could not read 0x%zX bytes!\n", shader_size);
        return 1;
    }
    ret = translate_shader(shader_data, shader_size, stage);
    free(shader_data);
    fclose(file);

    return ret;
}

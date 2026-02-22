#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "miniscript_c.h"

bool dummy_from_string(void* user_data, const char* str, ms_bytes_t* out_key)
{
    (void)user_data;
    out_key->len = strlen(str);
    out_key->data = (uint8_t*)malloc(out_key->len);
    memcpy(out_key->data, str, out_key->len);
    return true;
}

bool dummy_to_string(void* user_data, const ms_bytes_t* key, char* out_str, size_t max_len)
{
    (void)user_data; 
    size_t copy_len = key->len < max_len - 1 ? key->len : max_len - 1;
    memcpy(out_str, key->data, copy_len);
    out_str[copy_len] = '\0';
    return true;
}

bool dummy_to_pk_bytes(void* user_data, const ms_bytes_t* key, ms_bytes_t* out_bytes)
{
    (void)user_data;
    out_bytes->len = 33; 
    out_bytes->data = (uint8_t*)calloc(33, 1); 
    out_bytes->data[0] = 0x02; 
    size_t copy_len = key->len < 32 ? key->len : 32;
    memcpy(out_bytes->data + 1, key->data, copy_len);

    return true;
}

bool dummy_from_pk_bytes(void* user_data, const uint8_t* bytes, size_t len, ms_bytes_t* out_key)
{
    (void)user_data;
    if (len != 33) return false;

    size_t str_len = 0;
    while (str_len < 32 && bytes[1 + str_len] != '\0')
    {
        str_len++;
    }

    out_key->len = str_len;
    out_key->data = (uint8_t*)malloc(str_len);
    memcpy(out_key->data, bytes + 1, str_len);
    return true;
}

void print_hex(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_full_api(const ms_context_t* ctx)
{
    printf("[*] Running comprehensive API test...\n");

    printf("    -> Compiling policy: and(pk(A),pk(B))\n");
    ms_node_t* node = ms_compile_policy("and(pk(A),pk(B))", ctx, NULL);
    assert(node != NULL);
    char* ms_string = ms_node_to_string(node, ctx);
    assert(ms_string != NULL);
    printf("    -> Miniscript String: %s\n", ms_string);

    size_t script_len = 0;
    uint8_t* script_bytes = ms_node_to_script(node, ctx, &script_len);
    assert(script_bytes != NULL);
    assert(script_len > 0);
    printf("    -> Raw Script (Hex):  ");
    print_hex(script_bytes, script_len);

    char* disasm = ms_disassemble_script(script_bytes, script_len);
    printf("    -> Disassembled:      %s\n", disasm);
    ms_string_free(disasm);

    printf("    -> Script Size: %zu bytes\n", ms_node_script_size(node));
    printf("    -> OP Count: %u\n", ms_node_get_ops(node));
    printf("    -> Max Stack Size: %u\n", ms_node_get_stack_size(node));
    assert(ms_node_check_ops_limit(node) == true);
    assert(ms_node_check_stack_size(node) == true);

    assert(ms_node_is_valid(node) == true);
    assert(ms_node_is_sane(node) == true);
    assert(ms_node_is_non_malleable(node) == true);
    assert(ms_node_needs_signature(node) == true);

    ms_fragment_t frag = ms_node_get_fragment(node);
    assert(frag == MS_FRAG_AND_V || frag == MS_FRAG_AND_B || frag == MS_FRAG_WRAP_C);

    printf("    -> Testing decode from raw bytes back to AST...\n");
    ms_node_t* reconstructed = ms_from_script(script_bytes, script_len, ctx);
    assert(reconstructed != NULL); 

    char* re_string = ms_node_to_string(reconstructed, ctx);
    assert(re_string != NULL);
    printf("    -> Reconstructed:     %s\n", re_string);

    assert(ms_node_compare(node, reconstructed) == 0);

    ms_string_free(ms_string);
    ms_string_free(re_string);
    ms_bytes_free(script_bytes);
    ms_node_free(node);
    ms_node_free(reconstructed);

    printf("    [PASS] Comprehensive API tests succeeded!\n\n");
}

void test_invalid_policy(const ms_context_t* ctx)
{
    printf("[*] Running invalid policy test...\n");

    ms_node_t* node = ms_compile_policy("invalid_policy_garbage()", ctx, NULL);
    assert(node == NULL);

    printf("    [PASS] Invalid policy was safely rejected.\n\n");
}

int main()
{
    printf("=== Starting Miniscript C Bindings Tests ===\n\n");

    ms_context_t ctx;
    memset(&ctx, 0, sizeof(ms_context_t));
    ctx.from_string = dummy_from_string;
    ctx.to_string = dummy_to_string;
    ctx.to_pk_bytes = dummy_to_pk_bytes;
    ctx.from_pk_bytes = dummy_from_pk_bytes;

    test_full_api(&ctx);
    test_invalid_policy(&ctx);

    printf("=== All tests passed successfully! ===\n");
    return 0;
}

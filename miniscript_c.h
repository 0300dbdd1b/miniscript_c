#ifndef MINISCRIPT_C_H
#define MINISCRIPT_C_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ms_node_opaque ms_node_t;

typedef enum
{
    MS_FRAG_JUST_0,
    MS_FRAG_JUST_1,
    MS_FRAG_PK_K,
    MS_FRAG_PK_H,
    MS_FRAG_OLDER,
    MS_FRAG_AFTER,
    MS_FRAG_SHA256,
    MS_FRAG_HASH256,
    MS_FRAG_RIPEMD160,
    MS_FRAG_HASH160,
    MS_FRAG_WRAP_A,
    MS_FRAG_WRAP_S,
    MS_FRAG_WRAP_C,
    MS_FRAG_WRAP_D,
    MS_FRAG_WRAP_V,
    MS_FRAG_WRAP_J,
    MS_FRAG_WRAP_N,
    MS_FRAG_AND_V,
    MS_FRAG_AND_B,
    MS_FRAG_OR_B,
    MS_FRAG_OR_C,
    MS_FRAG_OR_D,
    MS_FRAG_OR_I,
    MS_FRAG_ANDOR,
    MS_FRAG_THRESH,
    MS_FRAG_MULTI
} ms_fragment_t;

typedef enum
{
    MS_AVAIL_NO = 0,
    MS_AVAIL_YES = 1,
    MS_AVAIL_MAYBE = 2
}   ms_availability_t;

typedef struct
{
    uint8_t* data;
    size_t len;
}   ms_bytes_t;

typedef struct
{
    ms_bytes_t* elements;
    size_t count;
}   ms_stack_t;

typedef struct
{
    void* user_data;
    bool (*to_string)(void* user_data, const ms_bytes_t* key, char* out_str, size_t max_len);
    bool (*from_string)(void* user_data, const char* str, ms_bytes_t* out_key);
    bool (*to_pk_bytes)(void* user_data, const ms_bytes_t* key, ms_bytes_t* out_bytes);
    bool (*to_pkh_bytes)(void* user_data, const ms_bytes_t* key, ms_bytes_t* out_bytes);
    bool (*from_pk_bytes)(void* user_data, const uint8_t* bytes, size_t len, ms_bytes_t* out_key);
    bool (*from_pkh_bytes)(void* user_data, const uint8_t* bytes, size_t len, ms_bytes_t* out_key);
    int (*key_compare)(void* user_data, const ms_bytes_t* a, const ms_bytes_t* b);
    ms_availability_t (*sign)(void* user_data, const ms_bytes_t* key, ms_bytes_t* out_sig);
    bool (*check_older)(void* user_data, uint32_t n);
    bool (*check_after)(void* user_data, uint32_t n);
    ms_availability_t (*sat_sha256)(void* user_data, const uint8_t* hash32, ms_bytes_t* out_preimage);
    ms_availability_t (*sat_ripemd160)(void* user_data, const uint8_t* hash20, ms_bytes_t* out_preimage);
    ms_availability_t (*sat_hash256)(void* user_data, const uint8_t* hash32, ms_bytes_t* out_preimage);
    ms_availability_t (*sat_hash160)(void* user_data, const uint8_t* hash20, ms_bytes_t* out_preimage);
} ms_context_t;

ms_node_t* ms_compile_policy(const char* policy_str, const ms_context_t* ctx, double* avg_cost_out);
ms_node_t* ms_from_string(const char* miniscript_str, const ms_context_t* ctx);
ms_node_t* ms_from_script(const uint8_t* script_bytes, size_t script_len, const ms_context_t* ctx);
void       ms_node_free(ms_node_t* node);

ms_fragment_t       ms_node_get_fragment(const ms_node_t* node);
uint32_t            ms_node_get_k(const ms_node_t* node);
size_t              ms_node_get_data_len(const ms_node_t* node);
const uint8_t*      ms_node_get_data(const ms_node_t* node);
size_t              ms_node_get_num_subs(const ms_node_t* node);
const ms_node_t*    ms_node_get_sub(const ms_node_t* node, size_t index);
size_t              ms_node_get_num_keys(const ms_node_t* node);
bool                ms_node_get_key(const ms_node_t* node, size_t index, ms_bytes_t* out_key);

int                 ms_node_compare(const ms_node_t* a, const ms_node_t* b);

ms_availability_t   ms_node_satisfy(const ms_node_t* node, const ms_context_t* ctx, ms_stack_t* out_stack, bool nonmalleable);
void                ms_stack_free(ms_stack_t* stack);

char*       ms_node_to_string(const ms_node_t* node, const ms_context_t* ctx);
uint8_t*    ms_node_to_script(const ms_node_t* node, const ms_context_t* ctx, size_t* out_len);

char*       ms_disassemble_script(const uint8_t* script_bytes, size_t script_len);

void        ms_string_free(char* str);
void        ms_bytes_free(uint8_t* bytes);

bool        ms_node_has_type_property(const ms_node_t* node, char property);

size_t      ms_node_script_size(const ms_node_t* node);
uint32_t    ms_node_get_ops(const ms_node_t* node);
uint32_t    ms_node_get_stack_size(const ms_node_t* node);
bool        ms_node_check_ops_limit(const ms_node_t* node);
bool        ms_node_check_stack_size(const ms_node_t* node);

bool        ms_node_is_valid(const ms_node_t* node);
bool        ms_node_is_valid_top_level(const ms_node_t* node);
bool        ms_node_is_sane(const ms_node_t* node);
bool        ms_node_is_sane_subexpression(const ms_node_t* node);
bool        ms_node_is_non_malleable(const ms_node_t* node);
bool        ms_node_needs_signature(const ms_node_t* node);
bool        ms_node_check_time_locks_mix(const ms_node_t* node);
bool        ms_node_check_duplicate_key(const ms_node_t* node);

const ms_node_t* ms_node_find_insane_sub(const ms_node_t* node);

#ifdef __cplusplus
}
#endif
#endif

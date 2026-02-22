#include "miniscript_c.h"
#include "miniscript/compiler.h"
#include "miniscript/bitcoin/script/script.h"

#include <string>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <optional>

using InternalKey = std::vector<uint8_t>;

struct ms_node_opaque
{
    miniscript::NodeRef<InternalKey> inner;
    mutable std::vector<ms_node_t*> sub_wrappers;

    ~ms_node_opaque()
    {
        for (auto w : sub_wrappers)
        {
            if (w) delete w;
        }
    }
};

struct CCallbackContext
{
    using Key = InternalKey;
    const ms_context_t* c_ctx;

    CCallbackContext(const ms_context_t* ctx) : c_ctx(ctx) {}

    std::optional<std::string> ToString(const Key& key) const
    {
        if (!c_ctx || !c_ctx->to_string) return {};
        ms_bytes_t b_key{(uint8_t*)key.data(), key.size()};
        char buf[256];
        if (c_ctx->to_string(c_ctx->user_data, &b_key, buf, sizeof(buf)))
        {
            return std::string(buf);
        }
        return {};
    }

    template<typename I>
    std::optional<Key> FromString(I first, I last) const
    {
        if (!c_ctx || !c_ctx->from_string) return {};
        std::string str(first, last);
        ms_bytes_t b_key{nullptr, 0};
        if (c_ctx->from_string(c_ctx->user_data, str.c_str(), &b_key))
        {
            Key res(b_key.data, b_key.data + b_key.len);
            if (b_key.data) free(b_key.data);
            return res;
        }
        return {};
    }

    std::vector<unsigned char> ToPKBytes(const Key& key) const
    {
        if (!c_ctx || !c_ctx->to_pk_bytes) return key;
        ms_bytes_t b_key{(uint8_t*)key.data(), key.size()};
        ms_bytes_t out_bytes{nullptr, 0};
        if (c_ctx->to_pk_bytes(c_ctx->user_data, &b_key, &out_bytes))
        {
            std::vector<unsigned char> res(out_bytes.data, out_bytes.data + out_bytes.len);
            if (out_bytes.data) free(out_bytes.data);
            return res;
        }
        return {};
    }

    std::vector<unsigned char> ToPKHBytes(const Key& key) const
    {
        if (!c_ctx || !c_ctx->to_pkh_bytes) return key;
        ms_bytes_t b_key{(uint8_t*)key.data(), key.size()};
        ms_bytes_t out_bytes{nullptr, 0};
        if (c_ctx->to_pkh_bytes(c_ctx->user_data, &b_key, &out_bytes))
        {
            std::vector<unsigned char> res(out_bytes.data, out_bytes.data + out_bytes.len);
            if (out_bytes.data) free(out_bytes.data);
            return res;
        }
        return {};
    }

    template<typename I>
    std::optional<Key> FromPKBytes(I first, I last) const
    {
        if (!c_ctx || !c_ctx->from_pk_bytes) return {};
        ms_bytes_t out_key{nullptr, 0};
        if (c_ctx->from_pk_bytes(c_ctx->user_data, &(*first), std::distance(first, last), &out_key))
        {
            Key res(out_key.data, out_key.data + out_key.len);
            if (out_key.data) free(out_key.data);
            return res;
        }
        return {};
    }

    template<typename I>
    std::optional<Key> FromPKHBytes(I first, I last) const
    {
        if (!c_ctx || !c_ctx->from_pkh_bytes) return {};
        ms_bytes_t out_key{nullptr, 0};
        if (c_ctx->from_pkh_bytes(c_ctx->user_data, &(*first), std::distance(first, last), &out_key))
        {
            Key res(out_key.data, out_key.data + out_key.len);
            if (out_key.data) free(out_key.data);
            return res;
        }
        return {};
    }

    bool KeyCompare(const Key& a, const Key& b) const
    {
        if (!c_ctx || !c_ctx->key_compare) return a < b;
        ms_bytes_t ba{(uint8_t*)a.data(), a.size()};
        ms_bytes_t bb{(uint8_t*)b.data(), b.size()};
        return c_ctx->key_compare(c_ctx->user_data, &ba, &bb) < 0;
    }

    miniscript::Availability Sign(const Key& key, std::vector<unsigned char>& sig) const
    {
        if (!c_ctx || !c_ctx->sign) return miniscript::Availability::NO;
        ms_bytes_t b_key{(uint8_t*)key.data(), key.size()};
        ms_bytes_t out_sig{nullptr, 0};
        ms_availability_t avail = c_ctx->sign(c_ctx->user_data, &b_key, &out_sig);
        if (avail != MS_AVAIL_NO && out_sig.data)
        {
            sig.assign(out_sig.data, out_sig.data + out_sig.len);
            free(out_sig.data);
        }
        return (miniscript::Availability)avail;
    }

    bool CheckOlder(uint32_t n) const
    {
        return c_ctx && c_ctx->check_older && c_ctx->check_older(c_ctx->user_data, n);
    }

    bool CheckAfter(uint32_t n) const
    {
        return c_ctx && c_ctx->check_after && c_ctx->check_after(c_ctx->user_data, n);
    }

    miniscript::Availability SatSHA256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const
    {
        if (!c_ctx || !c_ctx->sat_sha256) return miniscript::Availability::NO;
        ms_bytes_t out_pre{nullptr, 0};
        ms_availability_t avail = c_ctx->sat_sha256(c_ctx->user_data, hash.data(), &out_pre);
        if (avail != MS_AVAIL_NO && out_pre.data)
        {
            preimage.assign(out_pre.data, out_pre.data + out_pre.len);
            free(out_pre.data);
        }
        return (miniscript::Availability)avail;
    }

    miniscript::Availability SatRIPEMD160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const
    {
        if (!c_ctx || !c_ctx->sat_ripemd160) return miniscript::Availability::NO;
        ms_bytes_t out_pre{nullptr, 0};
        ms_availability_t avail = c_ctx->sat_ripemd160(c_ctx->user_data, hash.data(), &out_pre);
        if (avail != MS_AVAIL_NO && out_pre.data)
        {
            preimage.assign(out_pre.data, out_pre.data + out_pre.len);
            free(out_pre.data);
        }
        return (miniscript::Availability)avail;
    }

    miniscript::Availability SatHASH256(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const
    {
        if (!c_ctx || !c_ctx->sat_hash256) return miniscript::Availability::NO;
        ms_bytes_t out_pre{nullptr, 0};
        ms_availability_t avail = c_ctx->sat_hash256(c_ctx->user_data, hash.data(), &out_pre);
        if (avail != MS_AVAIL_NO && out_pre.data)
        {
            preimage.assign(out_pre.data, out_pre.data + out_pre.len);
            free(out_pre.data);
        }
        return (miniscript::Availability)avail;
    }

    miniscript::Availability SatHASH160(const std::vector<unsigned char>& hash, std::vector<unsigned char>& preimage) const
    {
        if (!c_ctx || !c_ctx->sat_hash160) return miniscript::Availability::NO;
        ms_bytes_t out_pre{nullptr, 0};
        ms_availability_t avail = c_ctx->sat_hash160(c_ctx->user_data, hash.data(), &out_pre);
        if (avail != MS_AVAIL_NO && out_pre.data)
        {
            preimage.assign(out_pre.data, out_pre.data + out_pre.len);
            free(out_pre.data);
        }
        return (miniscript::Availability)avail;
    }
};

static miniscript::NodeRef<InternalKey> ConvertNode(const miniscript::NodeRef<CompilerContext::Key>& node, const CCallbackContext& ctx)
{
    if (!node) return nullptr;

    std::vector<miniscript::NodeRef<InternalKey>> new_subs;
    for (const auto& sub : node->subs)
    {
        new_subs.push_back(ConvertNode(sub, ctx));
    }

    std::vector<InternalKey> new_keys;
    for (const auto& key : node->keys)
    {
        auto converted = ctx.FromString(key.begin(), key.end());
        if (!converted) return nullptr;
        new_keys.push_back(std::move(*converted));
    }

    if (!new_keys.empty() && !new_subs.empty())
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, std::move(new_subs), std::move(new_keys), node->k);
    }
    else if (!new_keys.empty())
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, std::move(new_keys), node->k);
    }
    else if (!new_subs.empty() && !node->data.empty())
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, std::move(new_subs), node->data, node->k);
    }
    else if (!node->data.empty())
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, node->data, node->k);
    }
    else if (!new_subs.empty())
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, std::move(new_subs), node->k);
    }
    else
    {
        return miniscript::MakeNodeRef<InternalKey>(miniscript::internal::NoDupCheck{}, node->fragment, node->k);
    }
}


extern "C" {


ms_node_t* ms_compile_policy(const char* policy_str, const ms_context_t* ctx, double* avg_cost_out)
{
    if (!policy_str || !ctx) return nullptr;

    miniscript::NodeRef<CompilerContext::Key> string_ret;
    double cost = 0.0;

    if (!Compile(std::string(policy_str), string_ret, cost) || !string_ret)
    {
        return nullptr;
    }
    if (avg_cost_out) *avg_cost_out = cost;

    CCallbackContext cpp_ctx(ctx);
    auto generic_ret = ConvertNode(string_ret, cpp_ctx);
    if (!generic_ret) return nullptr;

    generic_ret->DuplicateKeyCheck(cpp_ctx);
    return new ms_node_t{std::move(generic_ret), {}};
}

ms_node_t* ms_from_string(const char* miniscript_str, const ms_context_t* ctx)
{
    if (!miniscript_str || !ctx) return nullptr;
    CCallbackContext cpp_ctx(ctx);
    auto ret = miniscript::FromString(std::string(miniscript_str), cpp_ctx);
    if (!ret) return nullptr;
    return new ms_node_t{std::move(ret), {}};
}

ms_node_t* ms_from_script(const uint8_t* script_bytes, size_t script_len, const ms_context_t* ctx)
{
    if (!script_bytes || !ctx || script_len == 0) return nullptr;
    CCallbackContext cpp_ctx(ctx);
    CScript script(script_bytes, script_bytes + script_len);
    auto ret = miniscript::FromScript(script, cpp_ctx);
    if (!ret) return nullptr;
    return new ms_node_t{std::move(ret), {}};
}

void ms_node_free(ms_node_t* node)
{
    if (node) delete node;
}

ms_fragment_t ms_node_get_fragment(const ms_node_t* node)
{
    if (!node || !node->inner) return MS_FRAG_JUST_0;
    return (ms_fragment_t)node->inner->fragment;
}

uint32_t ms_node_get_k(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->k : 0;
}

size_t ms_node_get_data_len(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->data.size() : 0;
}

const uint8_t* ms_node_get_data(const ms_node_t* node)
{
    return (node && node->inner && !node->inner->data.empty()) ? node->inner->data.data() : nullptr;
}

size_t ms_node_get_num_subs(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->subs.size() : 0;
}

const ms_node_t* ms_node_get_sub(const ms_node_t* node, size_t index)
{
    if (!node || !node->inner || index >= node->inner->subs.size()) return nullptr;

    if (node->sub_wrappers.empty())
    {
        node->sub_wrappers.resize(node->inner->subs.size(), nullptr);
    }

    if (!node->sub_wrappers[index])
    {
        node->sub_wrappers[index] = new ms_node_t{node->inner->subs[index], {}};
    }
    return node->sub_wrappers[index];
}

size_t ms_node_get_num_keys(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->keys.size() : 0;
}

bool ms_node_get_key(const ms_node_t* node, size_t index, ms_bytes_t* out_key)
{
    if (!node || !node->inner || !out_key || index >= node->inner->keys.size()) return false;
    const auto& key = node->inner->keys[index];
    out_key->len = key.size();
    out_key->data = (uint8_t*)malloc(key.size());
    if (out_key->data)
    {
        memcpy(out_key->data, key.data(), key.size());
        return true;
    }
    return false;
}

int ms_node_compare(const ms_node_t* a, const ms_node_t* b)
{
    if (!a || !a->inner) return (b && b->inner) ? -1 : 0;
    if (!b || !b->inner) return 1;
    return Compare(*a->inner, *b->inner);
}

ms_availability_t ms_node_satisfy(const ms_node_t* node, const ms_context_t* ctx, ms_stack_t* out_stack, bool nonmalleable)
{
    if (!node || !node->inner || !ctx || !out_stack) return MS_AVAIL_NO;

    CCallbackContext cpp_ctx(ctx);
    std::vector<std::vector<unsigned char>> stack;

    miniscript::Availability avail = node->inner->Satisfy(cpp_ctx, stack, nonmalleable);

    out_stack->count = stack.size();
    if (stack.empty())
    {
        out_stack->elements = nullptr;
    }
    else
    {
        out_stack->elements = (ms_bytes_t*)malloc(sizeof(ms_bytes_t) * stack.size());
        for (size_t i = 0; i < stack.size(); ++i)
        {
            out_stack->elements[i].len = stack[i].size();
            out_stack->elements[i].data = (uint8_t*)malloc(stack[i].size());
            memcpy(out_stack->elements[i].data, stack[i].data(), stack[i].size());
        }
    }
    return (ms_availability_t)avail;
}

void ms_stack_free(ms_stack_t* stack)
{
    if (!stack) return;
    if (stack->elements)
    {
        for (size_t i = 0; i < stack->count; ++i)
        {
            if (stack->elements[i].data) free(stack->elements[i].data);
        }
        free(stack->elements);
    }
    stack->count = 0;
    stack->elements = nullptr;
}

char* ms_node_to_string(const ms_node_t* node, const ms_context_t* ctx)
{
    if (!node || !node->inner || !ctx) return nullptr;
    CCallbackContext cpp_ctx(ctx);
    auto opt_str = node->inner->ToString(cpp_ctx);
    if (!opt_str) return nullptr;

    char* c_str = (char*)malloc(opt_str->length() + 1);
    if (c_str) memcpy(c_str, opt_str->c_str(), opt_str->length() + 1);
    return c_str;
}

uint8_t* ms_node_to_script(const ms_node_t* node, const ms_context_t* ctx, size_t* out_len)
{
    if (!node || !node->inner || !ctx || !out_len) return nullptr;
    CCallbackContext cpp_ctx(ctx);
    CScript script = node->inner->ToScript(cpp_ctx);

    *out_len = script.size();
    if (*out_len == 0) return nullptr;

    uint8_t* bytes = (uint8_t*)malloc(*out_len);
    if (bytes) memcpy(bytes, script.data(), *out_len);
    return bytes;
}

char* ms_disassemble_script(const uint8_t* script_bytes, size_t script_len)
{
    if (!script_bytes || script_len == 0) return nullptr;
    CScript script(script_bytes, script_bytes + script_len);

    std::string dis = Disassemble(script);
    if (dis.empty()) return nullptr;

    char* c_str = (char*)malloc(dis.length() + 1);
    if (c_str) memcpy(c_str, dis.c_str(), dis.length() + 1);
    return c_str;
}

void ms_string_free(char* str)
{
    if (str) free(str);
}

void ms_bytes_free(uint8_t* bytes)
{
    if (bytes) free(bytes);
}

bool ms_node_has_type_property(const ms_node_t* node, char property)
{
    if (!node || !node->inner) return false;

    char str[2] = {property, '\0'};
    try
    {
        miniscript::Type type_mask = miniscript::operator""_mst(str, 1);
        return node->inner->GetType() << type_mask;
    }
    catch (...)
    {
        return false;
    }
}

size_t ms_node_script_size(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->ScriptSize() : 0;
}

uint32_t ms_node_get_ops(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->GetOps() : 0;
}

uint32_t ms_node_get_stack_size(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->GetStackSize() : 0;
}

bool ms_node_check_ops_limit(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->CheckOpsLimit() : false;
}

bool ms_node_check_stack_size(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->CheckStackSize() : false;
}

bool ms_node_is_valid(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->IsValid() : false;
}

bool ms_node_is_valid_top_level(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->IsValidTopLevel() : false;
}

bool ms_node_is_sane(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->IsSane() : false;
}

bool ms_node_is_sane_subexpression(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->IsSaneSubexpression() : false;
}

bool ms_node_is_non_malleable(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->IsNonMalleable() : false;
}

bool ms_node_needs_signature(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->NeedsSignature() : false;
}

bool ms_node_check_time_locks_mix(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->CheckTimeLocksMix() : false;
}

bool ms_node_check_duplicate_key(const ms_node_t* node)
{
    return (node && node->inner) ? node->inner->CheckDuplicateKey() : false;
}

const ms_node_t* ms_node_find_insane_sub(const ms_node_t* node)
{
    if (!node || !node->inner) return nullptr;
    const auto* bad_node = node->inner->FindInsaneSub();
    if (!bad_node) return nullptr;

    auto bad_ref = miniscript::NodeRef<InternalKey>(bad_node, [](const auto*){});
    return new ms_node_t{std::move(bad_ref), {}}; 
}

} // extern "C"

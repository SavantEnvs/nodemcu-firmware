/*
 * Lua SOURCE load + run (what `luac.cross -e script.lua` does), built twice: against the NodeMCU
 * Lua 5.3 host tree (fuzz_lua53_exec) and the Lua 5.1 host tree (fuzz_lua51_exec). Exercises the
 * lexer, parser, code generator, VM, GC, ROTables and the linked NodeMCU modules (struct, sjson,
 * pipe, pixbuf, bit, color_utils) plus the stock string/table/math/coroutine libraries.
 *
 * Kept deterministic and bounded without timers:
 *  - a COUNT hook (instruction count, not wall clock) raises a Lua error after a fixed budget;
 *  - the allocator is capped (lua_fuzz_common.h).
 * Precompiled chunks are unverified by design in Lua ("maliciously crafted bytecode can crash the
 * interpreter", Lua manual §load), so the input is loaded in text mode only and the script's own
 * load()/loadstring() are restricted to text. Host-only filesystem/process libs (io, os, dofile,
 * loadfile, require, package) and the debug library are hidden: they are luac.cross host
 * conveniences, not firmware surface.
 */
#include "lua_fuzz_common.h"

#define FUZZ_INSN_BUDGET 2000000L
#define FUZZ_HOOK_STEP 1000

typedef struct { long left; } budget_t;
static budget_t *g_budget;

static void count_hook(lua_State *L, lua_Debug *ar) {
  (void)ar;
  g_budget->left -= FUZZ_HOOK_STEP;
  if (g_budget->left < 0)
    luaL_error(L, "instruction budget exhausted");
}

#if LUA_VERSION_NUM >= 503
static const char kPrelude[] =
  "debug, dofile, loadfile, require, package, io, os = false, false, false, false, false, false, false\n"
  "do local l = load; load = function(c, n, _, ...) return l(c, n, 't', ...) end end\n";
#define LOAD_TEXT(L, d, s) luaL_loadbufferx(L, (const char *)(d), s, "=fuzz", "t")
#else
static const char kPrelude[] =
  "debug, dofile, loadfile, require, package, io, os = false, false, false, false, false, false, false\n"
  "do local ls = loadstring\n"
  "  loadstring = function(s, n) if type(s) == 'string' and s:byte(1) == 27 then return nil, 'binary chunk' end return ls(s, n) end\n"
  "  load = function(f, n) local t = {} while true do local p = f() if p == nil or p == '' then break end t[#t+1] = p end return loadstring(table.concat(t), n) end\n"
  "end\n";
/* Lua 5.1 has no mode argument: luaL_loadbuffer treats a leading LUA_SIGNATURE[0] as a binary chunk. */
static int LOAD_TEXT(lua_State *L, const uint8_t *d, size_t s) {
  if (s > 0 && d[0] == LUA_SIGNATURE[0])
    return -1;
  return luaL_loadbuffer(L, (const char *)d, s, "=fuzz");
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#if LUA_VERSION_NUM < 503
  if (size > 0 && data[0] == LUA_SIGNATURE[0])
    return -1; /* binary chunk: see LOAD_TEXT */
#endif
  budget_t b = { FUZZ_INSN_BUDGET };
  g_budget = &b;
  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  if (fuzz_openlibs(L) == 0 && luaL_loadbuffer(L, kPrelude, sizeof(kPrelude) - 1, "=prelude") == 0 &&
      lua_pcall(L, 0, 0, 0) == 0) {
    if (LOAD_TEXT(L, data, size) == 0) {
      lua_sethook(L, count_hook, LUA_MASKCOUNT, FUZZ_HOOK_STEP);
      lua_pcall(L, 0, 0, 0);
      lua_sethook(L, NULL, 0, 0);
    }
  }
  lua_close(L);
  g_budget = NULL;
  return 0;
}

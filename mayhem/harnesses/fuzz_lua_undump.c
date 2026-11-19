/*
 * Lua BYTECODE loader (lundump.c: luaU_undump, NodeMCU's modified chunk format), built against the
 * Lua 5.3 host tree (fuzz_lua53_undump) and the Lua 5.1 host tree (fuzz_lua51_undump). This is what
 * `luac.cross -l file.lc` and the firmware's loading of .lc files go through.
 *
 * The chunk is only LOADED, never run: Lua does not verify bytecode, so executing a malformed chunk
 * crashing the VM is by design (Lua manual, §load). A chunk that loads is dumped back (lua_dump). Seeds are chunks made by luac.cross itself.
 */
#include "lua_fuzz_common.h"

static int discard_writer(lua_State *L, const void *p, size_t sz, void *ud) {
  (void)L; (void)p; (void)ud;
  return sz > (size_t)1 << 30; /* never true for a loaded chunk; keeps the writer non-trivial */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
#if LUA_VERSION_NUM < 503
  /* Lua 5.1 picks binary mode only when the chunk starts with LUA_SIGNATURE[0]; anything else would
   * go to the source parser, which fuzz_lua51_exec covers. */
  if (size == 0 || data[0] != LUA_SIGNATURE[0])
    return -1;
#endif
  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  if (fuzz_openlibs(L) == 0) {
#if LUA_VERSION_NUM >= 503
    if (luaL_loadbufferx(L, (const char *)data, size, "=fuzz", "b") == LUA_OK)
      lua_dump(L, discard_writer, NULL, 0); /* re-serialise what the loader built (ldump.c) */
#else
    if (luaL_loadbuffer(L, (const char *)data, size, "=fuzz") == 0)
      lua_dump(L, discard_writer, NULL, 0);
#endif
  }
  lua_close(L);
  return 0;
}

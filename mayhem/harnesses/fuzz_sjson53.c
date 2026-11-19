/*
 * sjson module (app/modules/sjson.c over the jsonsl streaming parser, app/sjson/jsonsl.c) through its
 * Lua API, Lua 5.3 host build.
 *
 * The input is JSON text. It is decoded three ways — sjson.decode(), sjson.decode() with the
 * metatable/null options, and a streaming sjson.decoder() fed in chunks whose size is taken from the
 * first byte — and a successful result is re-encoded with sjson.encode().
 */
#include "lua_fuzz_common.h"

static const char kDriver[] =
  "local s, chunk = ...\n"
  "local ok, v = pcall(sjson.decode, s)\n"
  "if ok then pcall(sjson.encode, v) end\n"
  "pcall(sjson.decode, s, {metatable = {}, null = false, depth = 8})\n"
  "local okd, d = pcall(sjson.decoder, {null = sjson.NULL})\n"
  "if okd then\n"
  "  local i, good = 1, true\n"
  "  while good and i <= #s do\n"
  "    good = pcall(d.write, d, s:sub(i, i + chunk - 1))\n"
  "    i = i + chunk\n"
  "  end\n"
  "  local okr, r = pcall(d.result, d)\n"
  "  if okr and r ~= nil then pcall(sjson.encode, r) end\n"
  "end\n";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int chunk = size ? (data[0] % 16) + 1 : 1;
  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  if (fuzz_openlibs(L) == LUA_OK &&
      luaL_loadbufferx(L, kDriver, sizeof(kDriver) - 1, "=driver", "t") == LUA_OK) {
    lua_pushlstring(L, (const char *)data, size);
    lua_pushinteger(L, chunk);
    lua_pcall(L, 2, 0, 0);
  }
  lua_close(L);
  return 0;
}

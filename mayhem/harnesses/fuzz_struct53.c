/*
 * struct module (app/modules/struct.c) through its Lua API, Lua 5.3 host build.
 * Reaches getnum/optsize/controloptions (upstream fix 64f0d377, "integer overflow in getnum").
 *
 * Input: <format string> NUL <data>. With no NUL the whole input is the format and data is empty.
 *   struct.size(fmt); vals = {struct.unpack(fmt, data)}; struct.pack(fmt, vals...)
 * every call protected (lua_pcall): Lua errors are normal rejections, only memory errors and UB matter.
 */
#include "lua_fuzz_common.h"

static const char kDriver[] =
  "local fmt, data = ...\n"
  "pcall(struct.size, fmt)\n"
  "local r = table.pack(pcall(struct.unpack, fmt, data))\n"
  "if r[1] then pcall(struct.pack, fmt, table.unpack(r, 2, r.n - 1)) end\n"
  "pcall(struct.unpack, fmt, data, 2)\n";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const uint8_t *nul = memchr(data, 0, size);
  size_t flen = nul ? (size_t)(nul - data) : size;
  const char *rest = nul ? (const char *)nul + 1 : "";
  size_t rlen = nul ? size - flen - 1 : 0;

  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  if (fuzz_openlibs(L) == LUA_OK &&
      luaL_loadbufferx(L, kDriver, sizeof(kDriver) - 1, "=driver", "t") == LUA_OK) {
    lua_pushlstring(L, (const char *)data, flen);
    lua_pushlstring(L, rest, rlen);
    lua_pcall(L, 2, 0, 0);
  }
  lua_close(L);
  return 0;
}

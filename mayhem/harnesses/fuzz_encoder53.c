/*
 * encoder module (app/modules/encoder.c) through its Lua API, Lua 5.3 host build: the decoders
 * fromBase64 / fromHex take untrusted text (HTTP bodies, MQTT payloads, config); toBase64 / toHex
 * are run on the decoded bytes and on the raw input.
 *
 * encoder.c is not in luac.cross's module list (app/lua53/linit.c), so build.sh compiles it on its
 * own and this harness publishes its ROTable as the global `encoder` with lua_pushrotable, which
 * is what the firmware's rotables table does for every NODEMCU_MODULE.
 * Every call is protected (lua_pcall): Lua errors ("invalid base64 string" ...) are normal
 * rejections, only memory errors and UB matter. A fresh lua_State per input (lua_fuzz_common.h).
 */
#include "lua_fuzz_common.h"
#include "lnodemcu.h"

extern const ROTable encoder_ROTable; /* LROT_END(encoder, ...) in encoder.c */

static const char kDriver[] =
  "local s = ...\n"
  "local ok, b = pcall(encoder.fromBase64, s)\n"
  "if ok then pcall(encoder.toBase64, b) end\n"
  "local ok2, h = pcall(encoder.fromHex, s)\n"
  "if ok2 then pcall(encoder.toHex, h) end\n"
  "pcall(encoder.toBase64, s)\n"
  "pcall(encoder.toHex, s)\n";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  if (fuzz_openlibs(L) == LUA_OK) {
    lua_pushrotable(L, &encoder_ROTable);
    lua_setglobal(L, "encoder");
    if (luaL_loadbufferx(L, kDriver, sizeof(kDriver) - 1, "=driver", "t") == LUA_OK) {
      lua_pushlstring(L, (const char *)data, size);
      lua_pcall(L, 1, 0, 0);
    }
  }
  lua_close(L);
  return 0;
}

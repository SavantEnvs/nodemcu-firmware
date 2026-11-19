/*
 * Shared helpers for the NodeMCU Lua harnesses (Lua 5.3 tree app/lua53 and Lua 5.1 tree app/lua).
 *
 * Each input gets a FRESH lua_State (luaL_newstate + luaL_openlibs, exactly as luac.cross does),
 * which is closed afterwards, so no Lua state survives from one input to the next.
 *
 * The state's allocator is wrapped with a per-state byte cap so a script like string.rep("x",1e10)
 * gets Lua's own "not enough memory" error instead of exhausting the fuzzer's RSS limit. The cap is
 * part of Lua's documented lua_Alloc contract (returning NULL = allocation failure).
 */
#ifndef NODEMCU_LUA_FUZZ_COMMON_H
#define NODEMCU_LUA_FUZZ_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

/* luac.c (luac.cross's main, not linked into the harnesses) defines the LFS image name the Lua 5.3
 * startup hook reads (lnodemcu.c); NULL = no image pending, as at a normal boot. */
char *LFSimageName = NULL;

#define FUZZ_LUA_MEM_CAP (64u * 1024u * 1024u)

typedef struct {
  lua_Alloc orig;
  void *orig_ud;
  long long used; /* signed: blocks allocated before the swap are freed through us */
} fuzz_alloc_t;

static void *fuzz_capped_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
  fuzz_alloc_t *a = (fuzz_alloc_t *)ud;
  size_t old = ptr ? osize : 0;
  if (nsize > old && (nsize - old > FUZZ_LUA_MEM_CAP ||
                      a->used + (long long)(nsize - old) > (long long)FUZZ_LUA_MEM_CAP))
    return NULL;
  void *r = a->orig(a->orig_ud, ptr, osize, nsize);
  if (nsize == 0 || r != NULL)
    a->used = a->used - (long long)old + (long long)nsize;
  return r;
}

/* luaL_newstate() with the capped allocator installed. */
static lua_State *fuzz_newstate(fuzz_alloc_t *a) {
  lua_State *L = luaL_newstate();
  if (L == NULL)
    return NULL;
  a->orig = lua_getallocf(L, &a->orig_ud);
  a->used = 0;
  lua_setallocf(L, fuzz_capped_alloc, a);
  return L;
}

static int fuzz_openlibs_k(lua_State *L) {
  luaL_openlibs(L);
  return 0;
}

/* luaL_openlibs inside a protected call (the NodeMCU LFS hook may throw from it). */
static int fuzz_openlibs(lua_State *L) {
  lua_pushcfunction(L, fuzz_openlibs_k);
  return lua_pcall(L, 0, 0, 0);
}

#endif

/*
 * LFS (Lua Flash Store) image loader, Lua 5.3 host build: the path `luac.cross -F image.img` takes
 * (lnodemcu.c luaN_init -> lundump.c luaU_undumpLFS / LoadAllProtos; upstream fix 1965a12e).
 *
 * Mirrors luac.c main(): the input is written to a scratch file named by LFSimageName (the variable
 * luac.c owns; this harness replaces luac.c), a state is opened and luaL_openlibs runs the NodeMCU
 * startup hook, which erases the emulated flash region, undumps the image into it and throws
 * "!LFSrestart!" (or the load error). Then, as luac.c does, the "restart": a second state is opened
 * with no image pending, which maps the freshly written LFS header, RO string table and module
 * index from flash, and a module lookup is done through the LFS index (without running any LFS
 * function: bytecode is unverified by design).
 *
 * State across inputs: the emulated flash region (LFSregion, allocated once by lnodemcu.c) is
 * erased by every load, and each input's restart reads only what that input's own load wrote.
 */
#include <stdio.h>
#include <unistd.h>
#include "lua_fuzz_common.h"

/* LFSimageName (luac.c owns it in luac.cross) is defined in lua_fuzz_common.h */

static char g_path[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  const char *tmp = getenv("TMPDIR");
  snprintf(g_path, sizeof g_path, "%s/nodemcu-lfs-XXXXXX", (tmp && *tmp) ? tmp : "/tmp");
  int fd = mkstemp(g_path);
  if (fd < 0) {
    perror("mkstemp");
    abort();
  }
  close(fd);
  return 0;
}

/* What node.LFS.list()/node.LFS.get(name) do after a restart: walk the LFS index and build a
 * closure for every module in it (not called), plus intern some strings through the RO table. */
static int restart_probe(lua_State *L) {
  luaL_pushlfsdts(L);
  lua_pop(L, 1);
  if (luaL_pushlfsmodules(L) == 0)
    return 0;
  int n = (int)lua_rawlen(L, -1);
  for (int i = 1; i <= n && i <= 256; i++) {
    lua_rawgeti(L, -1, i);
    if (lua_type(L, -1) == LUA_TSTRING)
      lua_pushlfsfunc(L);
    lua_pop(L, 1);
  }
  lua_pop(L, 1);
  lua_pushstring(L, "print");
  lua_pushstring(L, "a.b.c");
  lua_concat(L, 2);
  lua_pop(L, 1);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *f = fopen(g_path, "wb");
  if (f == NULL)
    abort();
  if (size && fwrite(data, 1, size, f) != size)
    abort();
  fclose(f);

  /* 1) boot with an image pending: luaN_init loads it and throws */
  LFSimageName = g_path;
  fuzz_alloc_t a;
  lua_State *L = fuzz_newstate(&a);
  if (L == NULL)
    return 0;
  int loaded = 0;
  if (fuzz_openlibs(L) != LUA_OK) {
    const char *m = lua_tostring(L, -1);
    loaded = (m && strcmp(m, "!LFSrestart!") == 0);
  }
  lua_close(L);
  LFSimageName = NULL; /* luaN_init's platform_rcr_delete also clears it */

  /* 2) restart with the loaded image mapped */
  if (loaded) {
    L = fuzz_newstate(&a);
    if (L != NULL) {
      if (fuzz_openlibs(L) == LUA_OK) {
        lua_pushcfunction(L, restart_probe);
        lua_pcall(L, 0, 0, 0);
      }
      lua_close(L);
    }
  }
  return 0;
}

#!/usr/bin/env bash
#
# mayhem/build.sh — NodeMCU firmware host-side code: the luac.cross host builds of both Lua trees
# (app/lua53 = Lua 5.3, app/lua = Lua 5.1, each with NodeMCU's ROTable/LFS changes and the struct,
# sjson, pipe, pixbuf, bit and color_utils modules linked in) plus the SDK-free codecs (CoAP, MQTT,
# uzlib inflate). Everything else in app/ needs the ESP8266 SDK + xtensa toolchain.
#
# Runs in the commit image as `mayhem` in /mayhem (base image ENV: CC, SANITIZER_FLAGS, ...).
#   1) test build: luac.cross (5.3 and 5.1) with upstream's Makefiles and normal flags, for test.sh
#   2) fuzz build: the same Makefiles with $SANITIZER_FLAGS $DEBUG_FLAGS + SanCov, objects only
#   3) each harness linked twice: libFuzzer (/mayhem/<t>) and run-once reproducer (/mayhem/<t>-standalone)
#   4) uzlib inflate through upstream's host unzip driver (/mayhem/uz_unzip_afl, libFuzzer)
#   also: the encoder module (Lua 5.3) and the FatFs SD-card filesystem (app/fatfs), see 3) / 3b)
#
# Upstream's host Makefiles hard-code `CC := gcc` and write objects under the (not gitignored)
# app/*/.output; the build overrides CC, ODIR, IMAGE and LDFLAGS on the make command line, so every
# object lands in mayhem/out/ (gitignored) and no upstream file is edited.
#
# Sanitizer relaxations (both per source file, through the Makefiles' own COPTS_<file> hook):
#  - ltable.c without ASan and UBSan `alignment`: rotable_findentry compares ROTable keys as
#    unaligned 4-byte words (`*(lu_int32 *)strkey`, ltable.c "safe 4-byte comparison for all
#    supported NodeMCU hosts"), reading up to 3 bytes past short string literals and heap strings on
#    every global lookup, so with ASan every program aborts during luaL_openlibs.
#  - lcode.c (Lua 5.3) without UBSan `pointer-overflow`: luaK_addlineinfo computes
#    `f->lineinfo + fs->sizelineinfo - 1` while lineinfo is still NULL on every compile.
#  - lundump.c without UBSan `nonnull-attribute` and `pointer-overflow`: LoadProtos does
#    memset(NULL, 0, 0) for every function without nested prototypes, and the LFS loader computes
#    `getstr(Tname) + OFFSET_TSTRING` (a negative offset as unsigned) for every module name, i.e. on
#    every valid chunk / LFS image (Lua 5.3; in 5.1 the flags are inert).
#  - lundump.c (Lua 5.3) also without UBSan `shift-base` and `signed-integer-overflow`: LoadInt /
#    LoadInteger decode the dump's varints as `x = (x<<7) + (b & 0x7f)` on a signed lua_Integer,
#    which is a 32-bit int in this build (and LoadInteger returns `-x-1`). The shift is UB from the
#    5th varint byte on (shift-base: "left shift of ... cannot be represented in type
#    'lua_Integer'"), and the add / negation can then overflow too. The relaxation mirrors what the
#    firmware's own compiler does (xtensa gcc wraps; luac.cross and the device load the same dumps).
#    It is not neutral: a wrapped varint can decode as a negative count, which no in-range varint
#    does, and that count reaches code behind it (e.g. luac.cross re-dumping it through DumpInt,
#    ldump.c, whose `x >>= 7` loop on a negative x writes below its buffer). With the checks halting,
#    this one cause was the first frame of 21 of fuzz_lfs53's 33 and 18 of fuzz_lua53_undump's 23
#    defects in run 3, and every input with a long varint aborted before the string / prototype / GC
#    code behind it.
#  - app/mqtt/mqtt_msg.c without UBSan `shift` and `signed-integer-overflow`: mqtt_get_total_length
#    (and the publish topic/data getters) decode the remaining-length varint as
#    `totlen += (buffer[i] & 0x7f) << (7 * (i - 1))` on int with no limit on the number of bytes, so
#    every segment with 5+ continuation bytes halted there (defect "left shift of ... by 28 places",
#    mqtt_msg.c:135). As with lundump.c this mirrors the device build, where the value wraps, and it
#    exposes what mqtt.c then does with a wrapped (negative) message_length: it advances in_buffer
#    by it.
#  - app/sjson/jsonsl.c without UBSan `shift`: its character-class bit tables test
#    `bits[c >> 5] & (1 << (31 - (c & 31)))` on int, i.e. 1 << 31, for every character parsed.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must point at the run-once driver (base image)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
H="$SRC/mayhem/harnesses"
mkdir -p "$OUT"

# directory of each Lua tree's host Makefile
declare -A LUADIR=([53]="app/lua53/host" [51]="app/lua/luac_cross")

# ---- 1) test build (normal flags) -------------------------------------------------------------
for v in 53 51; do
  make -C "${LUADIR[$v]}" LUA="$v" CC="$CC" \
    EXTRA_CCFLAGS="$COVERAGE_FLAGS" LDFLAGS="-lm -ldl $COVERAGE_FLAGS" \
    ODIR="$OUT/test$v/obj" IMAGE="$OUT/test$v/luac.cross" all
done

# ---- 2) fuzz build of both Lua trees (objects only) -------------------------------------------
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
for v in 53 51; do
  odir="$OUT/fuzz$v/obj"
  objs=$(make -s -C "${LUADIR[$v]}" LUA="$v" CC="$CC" ODIR="$odir" test | sed -n 's/^OBJS: //p')
  make -C "${LUADIR[$v]}" LUA="$v" CC="$CC" EXTRA_CCFLAGS="$FUZZ_CFLAGS" \
    COPTS_ltable="-fno-sanitize=address,alignment" COPTS_lcode="-fno-sanitize=pointer-overflow" \
    COPTS_jsonsl="-fno-sanitize=shift" COPTS_lundump="-fno-sanitize=nonnull-attribute,pointer-overflow,shift-base,signed-integer-overflow" \
    ODIR="$odir" $objs
  # everything but luac.cross's own driver: luac.o (main) and, in 5.1, lflashimg.o (the `-f` image
  # writer, which calls luac.c's luac_fatal)
  printf '%s\n' $objs | grep -Ev '/(luac|lflashimg)\.o$' > "$OUT/fuzz$v/objs.txt"
done
# the encoder module (app/modules/encoder.c), not part of luac.cross: compiled by the 5.3 Makefile's
# own rule (its vpath includes app/modules) for fuzz_encoder53 only. It uses the ESP SDK's `uint8`
# (c_types.h / sdk-overrides/include/stdint.h: unsigned char), which the host has as uint8_t.
make -C "${LUADIR[53]}" LUA=53 CC="$CC" EXTRA_CCFLAGS="$FUZZ_CFLAGS" COPTS_encoder="-Duint8=uint8_t" \
  ODIR="$OUT/fuzz53/obj" "$OUT/fuzz53/obj/encoder.o"

# ---- 2b) fuzz build of the SDK-free codecs ----------------------------------------------------
CODEC="$OUT/codec"
mkdir -p "$CODEC"
CODEC_INC="-DLUA_USE_HOST -Ddbg_printf=printf -Iapp/include -Iapp/coap -Iapp/lua53 -Iapp -Iapp/uzlib -Iapp/mqtt"
for f in app/coap/coap.c app/coap/coap_server.c app/coap/uri.c app/coap/str.c app/coap/pdu.c \
         app/mqtt/mqtt_msg.c; do
  o="$CODEC/$(basename "${f%.c}").o"
  extra=""
  [ "$f" != app/mqtt/mqtt_msg.c ] || extra="-fno-sanitize=shift,signed-integer-overflow"
  # dbg_printf (NODE_ERR) is the platform's debug print: printf on the host. coap.c's coap_setup()
  # calls the SDK's os_random() without a declaration; it is supplied by coap_sdk_stubs.c.
  [ "$o" -nt "$f" ] || $CC $FUZZ_CFLAGS -O1 -ffunction-sections -fdata-sections \
    -Wno-error=implicit-function-declaration $extra $CODEC_INC -c "$f" -o "$o"
done

# ---- 3) harnesses -----------------------------------------------------------------------------
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# link <name> <harness.c> <cflags> <objects...>
link() {
  local name="$1" src="$2" cflags="$3"; shift 3
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $cflags -c "$src" -o "$OUT/$name.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$@" "$OUT/lsan_off.o" \
    -Wl,--gc-sections -lm -ldl -o "$SRC/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$@" "$OUT/lsan_off.o" \
    -Wl,--gc-sections -lm -ldl -o "$SRC/$name-standalone"
}

LUA53_INC="-Iapp/lua53/host -Iapp/lua53 -Iapp/include -Iapp/uzlib -Iapp"
LUA51_INC="-DLUA_CROSS_COMPILER -Iapp/lua/luac_cross -Iapp/lua -Iapp/include -Iapp/uzlib -Iapp"
mapfile -t O53 < "$OUT/fuzz53/objs.txt"
mapfile -t O51 < "$OUT/fuzz51/objs.txt"

link fuzz_struct53      "$H/fuzz_struct53.c"   "$LUA53_INC" "${O53[@]}"
link fuzz_sjson53       "$H/fuzz_sjson53.c"    "$LUA53_INC" "${O53[@]}"
link fuzz_lfs53         "$H/fuzz_lfs53.c"      "$LUA53_INC" "${O53[@]}"
link fuzz_lua53_exec    "$H/fuzz_lua_exec.c"   "$LUA53_INC" "${O53[@]}"
link fuzz_lua53_undump  "$H/fuzz_lua_undump.c" "$LUA53_INC" "${O53[@]}"
link fuzz_lua51_exec    "$H/fuzz_lua_exec.c"   "$LUA51_INC" "${O51[@]}"
link fuzz_lua51_undump  "$H/fuzz_lua_undump.c" "$LUA51_INC" "${O51[@]}"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $CODEC_INC -c "$H/coap_sdk_stubs.c" -o "$CODEC/coap_sdk_stubs.o"
COAP_OBJS=("$CODEC/coap.o" "$CODEC/coap_server.o" "$CODEC/uri.o" "$CODEC/str.o" "$CODEC/pdu.o" "$CODEC/coap_sdk_stubs.o")
link fuzz_coap_parse    "$H/fuzz_coap_parse.c" "$CODEC_INC" "${COAP_OBJS[@]}"
link fuzz_coap_uri      "$H/fuzz_coap_uri.c"   "$CODEC_INC" "${COAP_OBJS[@]}"
link fuzz_mqtt_msg      "$H/fuzz_mqtt_msg.c"   "$CODEC_INC" "$CODEC/mqtt_msg.o"
link fuzz_encoder53     "$H/fuzz_encoder53.c"  "$LUA53_INC" "$OUT/fuzz53/obj/encoder.o" "${O53[@]}"

# ---- 3b) FatFs (app/fatfs: ff.c + ffunicode.c + ffsystem.c, NodeMCU's ffconf.h), the SD-card
# filesystem, with upstream's own flags from app/fatfs/Makefile (-std=gnu11, -imacros
# fatfs_prefix_lib.h); the harness supplies the diskio layer over the fuzz input.
FATOUT="$OUT/fatfs"
mkdir -p "$FATOUT"
FAT_INC="-std=gnu11 -imacros app/fatfs/fatfs_prefix_lib.h -Iapp/fatfs -Iapp/include"
for f in app/fatfs/ff.c app/fatfs/ffunicode.c app/fatfs/ffsystem.c; do
  o="$FATOUT/$(basename "${f%.c}").o"
  [ "$o" -nt "$f" ] || $CC $FUZZ_CFLAGS -O1 $FAT_INC -c "$f" -o "$o"
done
link fuzz_fatfs "$H/fuzz_fatfs.c" "$FAT_INC" "$FATOUT/ff.o" "$FATOUT/ffunicode.o" "$FATOUT/ffsystem.o"

# ---- 4) uzlib inflate: mayhem/harnesses/fuzz_uz_unzip.c runs upstream's host driver
# app/uzlib/host/uz_unzip.c (its byte callbacks, main() replaced by an in-memory version) over the
# fuzz input. The target keeps its original name, uz_unzip_afl, although it is now a libFuzzer
# target: as an AFL file-input CLI it recorded 0 edges in Mayhem.
UZOUT="$OUT/uzlib"
mkdir -p "$UZOUT"
for f in app/uzlib/uzlib_inflate.c app/uzlib/crc32.c; do
  o="$UZOUT/$(basename "${f%.c}").o"
  [ "$o" -nt "$f" ] || $CC $FUZZ_CFLAGS -O1 -Iapp/uzlib -c "$f" -o "$o"
done
link uz_unzip_afl "$H/fuzz_uz_unzip.c" "-Iapp/uzlib" "$UZOUT/uzlib_inflate.o" "$UZOUT/crc32.o"

echo "build.sh: done"

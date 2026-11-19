/*
 * libFuzzer harness for uzlib_inflate (app/uzlib/uzlib_inflate.c), the streaming RFC1951/gzip
 * inflater the firmware uses to load compressed LFS images (app/lua/lflash.c).
 *
 * It drives upstream's own host driver, app/uzlib/host/uz_unzip.c: that file's get_byte /
 * put_byte / recall_byte / processOutRec callbacks are used unchanged; only its main() (renamed
 * here) is replaced by an in-memory version of the same sequence:
 *   - the input is the .gz image (read through a FILE* over the fuzz bytes),
 *   - its last 4 bytes give the expanded length (gzip ISIZE), as in uz_unzip.c and lflash.c,
 *   - output goes to /dev/null, with the CRC checked against the gzip trailer.
 * Like the on-device loader (lflash.c loadLFS), all WRITE_BLOCKS output blocks are allocated up
 * front and any ISIZE is accepted (lflash.c does not reject ISIZE <= 0); the host tool's main()
 * allocates fewer blocks for small ISIZE values and an ISIZE <= 0 leaves block[0] NULL, which is a
 * quirk of that CLI, not of the inflater.
 *
 * Output bound: on the device the inflated image is an LFS image, which lflash.c's procFirstPass
 * rejects (flash_error) once its header's flash_size exceeds the LFS partition; NodeMCU's LFS is
 * at most 256 KiB (docs/index.md: "up to 256Kb Lua code and read-only constants"), plus the relocation flag vector (one bit per
 * word, i.e. 1/32 of that). The harness bounds the output the same way: put_byte is wrapped so
 * that the byte after LFS_MAX_OUTPUT ends the inflate with UZLIB_DATA_ERROR, thrown with
 * UZLIB_THROW, the error path upstream's own get_byte callback uses (uzlib_inflate catches it
 * itself and returns the error code).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define main uz_unzip_host_main
#include "../../app/uzlib/host/uz_unzip.c"
#undef main

#define LFS_MAX_OUTPUT (0x40000 + 0x40000 / 32)

static void put_byte_bounded(uint8_t value) {
  if (out->ndx >= LFS_MAX_OUTPUT)
    UZLIB_THROW(UZLIB_DATA_ERROR);
  put_byte(value);
}

static struct INPUT  in_storage;
static struct OUTPUT out_storage;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int i, res;
  uint32_t crc = 0;
  void *state = NULL;

  if (size < 4 || size > INT32_MAX)
    return -1; /* the 4-byte ISIZE trailer must exist (uz_unzip.c and lflash.c read it); in->len is int */

  in  = &in_storage;
  out = &out_storage;
  memset(in, 0, sizeof(*in));
  memset(out, 0, sizeof(*out));

  memcpy(&out->len, data + size - 4, 4);
  in->len = (int)size;

  in->fin = fmemopen((void *)data, size, "rb");
  if (!in->fin)
    return 0;
  out->fout = fopen("/dev/null", "wb");
  if (!out->fout) {
    fclose(in->fin);
    return 0;
  }

  for (i = 0; i < WRITE_BLOCKS; i++)
    out->block[i] = uz_malloc(sizeof(outBlock));

  out->breakNdx  = (out->len < WRITE_BLOCKSIZE) ? out->len : WRITE_BLOCKSIZE;
  out->fullBlkCB = processOutRec;
  out->crc       = ~0;

  res = uzlib_inflate(get_byte, put_byte_bounded, recall_byte, in->len, &crc, &state);
  if (res > 0 && crc != ~out->crc)
    res = UZLIB_CHKSUM_ERROR;
  (void)res;

  /* processOutRec closes fout (and clears the callback) once the declared length is written */
  if (out->fullBlkCB)
    fclose(out->fout);
  for (i = 0; i < WRITE_BLOCKS; i++)
    FREE(out->block[i]);
  fclose(in->fin);
  return 0;
}

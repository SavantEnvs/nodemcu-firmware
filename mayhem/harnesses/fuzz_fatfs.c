/*
 * FatFs (app/fatfs/ff.c, with ffunicode.c / ffsystem.c and NodeMCU's ffconf.h) over an SD-card
 * image: the fuzz input is the raw card (512-byte sectors), so the MBR partition table, the FAT
 * boot sector / BPB, the FAT and the directory entries (SFN + LFN) are all attacker data, as on a
 * removable card.
 *
 * The calls follow what NodeMCU's file module does through app/fatfs/myfatfs.c:
 *   f_mount(&fs, "SD0:", 1)            (myfatfs_mount; logical drive SD0 = VolToPart[0], the
 *                                       card's 1st partition, upstream's app/include/fatfs_config.h)
 *   f_getfree / f_getlabel / f_stat    (myfatfs_fsinfo, file.stat)
 *   f_opendir + f_readdir loop         (file.list), one level of subdirectories (f_chdir/f_getcwd)
 *   f_open + f_read + f_lseek          (file.open "r" / read / seek) on the files found
 *   f_open(FA_CREATE_ALWAYS|FA_WRITE) + f_write + f_sync, f_mkdir, f_rename, f_unlink
 *                                      (file.open "w", file.rename, file.remove) — cluster
 *                                       allocation over the card's (possibly corrupt) FAT
 *   f_mount(NULL, "SD0:", 0)            (myfatfs_umount)
 *
 * The disk is a private, zero-padded copy of the input (disk_write changes only the copy), so each
 * input's result depends only on that input. FatFs keeps no state beyond the FATFS object and the
 * VolToPart table, which is read-only here. The walk is bounded (entries, files, bytes read) so a
 * large but valid image finishes; the bounds are not checks on the input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ff.h"
#include "diskio.h"
#include "fatfs_config.h" /* upstream's VolToPart table (logical drive -> SS pin, partition) */

#define SECTOR 512
#define MAX_ENTRIES 64
#define MAX_FILES 16
#define MAX_READ 8192
/* zero bytes kept after every path's NUL: see the create_name note in LLVMFuzzerTestOneInput */
#define PATH_SLACK 8

static uint8_t *disk;
static size_t disk_sectors;
static volatile uint32_t sink;

/* ---- diskio over the fuzz buffer (app/platform/sdcard.c on the device) ---- */
DSTATUS disk_initialize(BYTE pdrv) { (void)pdrv; return 0; }
DSTATUS disk_status(BYTE pdrv) { (void)pdrv; return 0; }

DRESULT disk_read(BYTE pdrv, BYTE *buff, DWORD sector, UINT count) {
  (void)pdrv;
  if (sector >= disk_sectors || count > disk_sectors - sector)
    return RES_ERROR;
  memcpy(buff, disk + (size_t)sector * SECTOR, (size_t)count * SECTOR);
  return RES_OK;
}

DRESULT disk_write(BYTE pdrv, const BYTE *buff, DWORD sector, UINT count) {
  (void)pdrv;
  if (sector >= disk_sectors || count > disk_sectors - sector)
    return RES_ERROR;
  memcpy(disk + (size_t)sector * SECTOR, buff, (size_t)count * SECTOR);
  return RES_OK;
}

DRESULT disk_ioctl(BYTE pdrv, BYTE cmd, void *buff) {
  (void)pdrv;
  switch (cmd) {
  case CTRL_SYNC: return RES_OK;
  case GET_SECTOR_COUNT: *(DWORD *)buff = (DWORD)disk_sectors; return RES_OK;
  case GET_SECTOR_SIZE: *(WORD *)buff = SECTOR; return RES_OK;
  case GET_BLOCK_SIZE: *(DWORD *)buff = 1; return RES_OK;
  default: return RES_PARERR;
  }
}

/* myfatfs.c's RTC hook; a fixed time keeps runs deterministic */
DWORD get_fattime(void) { return ((DWORD)(2018 - 1980) << 25) | (1 << 21) | (1 << 16); }

static int files_read;

static void read_file(const char *path) {
  FIL f;
  if (files_read >= MAX_FILES || f_open(&f, path, FA_READ) != FR_OK)
    return;
  files_read++;
  uint8_t buf[1024];
  UINT br;
  size_t total = 0;
  while (total < MAX_READ && f_read(&f, buf, sizeof buf, &br) == FR_OK && br > 0) {
    total += br;
    sink ^= buf[0] ^ buf[br - 1];
  }
  if (f_lseek(&f, f_size(&f) / 2) == FR_OK && f_read(&f, buf, 16, &br) == FR_OK && br > 0)
    sink ^= buf[0];
  f_close(&f);
}

static void walk(const char *dir, int depth, int *entries) {
  DIR d;
  FILINFO fi;
  char path[2 * FF_MAX_LFN + 16 + PATH_SLACK];
  if (f_opendir(&d, dir) != FR_OK)
    return;
  while (*entries < MAX_ENTRIES && f_readdir(&d, &fi) == FR_OK && fi.fname[0]) {
    (*entries)++;
    memset(path, 0, sizeof path);
    snprintf(path, sizeof path - PATH_SLACK, "%s/%s", dir, fi.fname);
    FILINFO st;
    if (f_stat(path, &st) == FR_OK)
      sink ^= (uint32_t)st.fsize ^ st.fattrib;
    if (fi.fattrib & AM_DIR) {
      if (depth == 0 && f_chdir(path) == FR_OK) {
        char cwd[2 * FF_MAX_LFN + 16];
        if (f_getcwd(cwd, sizeof cwd) == FR_OK)
          sink ^= (uint8_t)cwd[0];
        walk(path, 1, entries);
        f_chdir("SD0:/");
      }
    } else {
      read_file(path);
    }
  }
  f_closedir(&d);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  disk_sectors = (size + SECTOR - 1) / SECTOR;
  if (disk_sectors == 0)
    return -1; /* no sector 0: f_mount cannot even read the MBR */
  disk = calloc(disk_sectors, SECTOR);
  if (!disk)
    return 0;
  memcpy(disk, data, size);
  files_read = 0;

  static FATFS fs; /* registered in ff.c's FatFs[] by f_mount; unregistered below */
  memset(&fs, 0, sizeof fs);
  if (f_mount(&fs, "SD0:", 1) == FR_OK) {
    DWORD nclst, vsn;
    FATFS *pfs;
    char label[24];
    if (f_getfree("SD0:", &nclst, &pfs) == FR_OK)
      sink ^= nclst;
    if (f_getlabel("SD0:", label, &vsn) == FR_OK)
      sink ^= vsn ^ (uint8_t)label[0];

    int entries = 0;
    walk("SD0:", 0, &entries);

    /* Paths live in buffers with room after the NUL: this FatFs version's create_name() reads one
     * byte past the terminator of every path it parses (ff.c:2852, `while (*p == '/' ...)` after
     * tchar2uni() has consumed the NUL), a constant 1-byte over-read independent of the card image
     * that ASan reports on the first string literal; on the device the paths come from Lua strings. */
    char p_file[32] = "SD0:/fz.txt", p_dir[32] = "SD0:/fzdir", p_moved[32] = "SD0:/fzdir/fz2.txt";
    FIL f;
    UINT bw;
    static const char msg[600] = "nodemcu fatfs fuzz";
    if (f_open(&f, p_file, FA_CREATE_ALWAYS | FA_WRITE) == FR_OK) {
      f_write(&f, msg, sizeof msg, &bw);
      f_sync(&f);
      f_close(&f);
    }
    f_mkdir(p_dir);
    f_rename(p_file, p_moved);
    read_file(p_moved);
    f_unlink(p_moved);
    f_unlink(p_dir);
  }
  f_mount(NULL, "SD0:", 0); /* also after a failed mount, which leaves &fs registered */
  free(disk);
  disk = NULL;
  return 0;
}

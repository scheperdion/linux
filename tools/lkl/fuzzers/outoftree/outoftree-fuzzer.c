// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <linux/uhid.h>
#include <linux/major.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <lkl/linux/time.h>
#include <lkl/linux/uhid.h>
#include <dlfcn.h>
#include <arpa/inet.h>


#include <lkl.h>
#include <lkl_host.h>

#include "outoftree-fuzzer.h"

void* MODULE_HANDLE = NULL;

static void fuzz_arbitrary_function(const uint8_t *data, size_t size) {
	sleep(2);
}

static int load_module(char* ko_path, char* arguments) {
      printf("Loading mod dependency %s\n", ko_path);
      void* MODULE_HANDLE = dlopen(ko_path, RTLD_GLOBAL | RTLD_LAZY);

      if (!MODULE_HANDLE) {
         printf("Error loading module dependency %s: %s\n", ko_path, dlerror());
         return -1;
      }
      void *this_module_dep = dlsym(MODULE_HANDLE, "__this_module");
      if(!this_module_dep) {
         printf("Error resolving __this_module for %s: %s\n", ko_path, dlerror());
         return -1;
      }
	  // Note(dion) fixup the init function that gets set to __GI_init_module by dlopen incorectly
	  void* init_handle = dlsym(MODULE_HANDLE, "init_module");
      int err = lkl_sys_init_loaded_module(this_module_dep, init_handle);
      if(err!=0) {
         printf("Error initializing module dependency %s\n", ko_path);
      }
      return err;
}

static int wrstr(const char *path, const char *val)
{
    int fd = lkl_sys_open(path, O_WRONLY | O_CLOEXEC, 0);
    if (fd < 0) { printf("Error open: %s\n", path); return -1; }
    if (lkl_sys_write(fd, val, strlen(val)) != (ssize_t)strlen(val)) {
        printf("write error: %s\n", path); lkl_sys_close(fd); return -1;
    }
    lkl_sys_close(fd);
    return 0;
}

static void load_usb_gadget() {
	const char *cfgfs = "/sysfs/kernel/config/usb_gadget";
	const char *gname = "rtlwifi";
	char path[512];

    /* 1. create directoreis  ----------------------------------------  */
	snprintf(path, sizeof(path), "%s/%s", cfgfs, gname);
	if (lkl_sys_mkdir(path, 0755)) { printf("mkdir gadget error"); return; }
	snprintf(path, sizeof(path), "%s/%s/strings/0x409", cfgfs, gname);
	if (lkl_sys_mkdir(path, 0755)) { printf("mkdir gadget strings error"); return; }
	snprintf(path, sizeof(path), "%s/%s/configs/c.1", cfgfs, gname);
	if (lkl_sys_mkdir(path, 0755)) { printf("mkdir gadget configs error"); return; }

    /* 2. Device descriptor fields ---------------------------------------- */
    snprintf(path, sizeof(path), "%s/%s/idVendor", cfgfs, gname);
    wrstr(path, "0x0bda");       /* Realtek */

    snprintf(path, sizeof(path), "%s/%s/idProduct", cfgfs, gname);
    wrstr(path, "0x0811");       /* RTL8812AU */

     /* 3. English-language string table ------------------------------------ */
    snprintf(path, sizeof(path), "%s/%s/strings/0x409/serialnumber", cfgfs, gname);
    wrstr(path, "deadbeef0123");
    snprintf(path, sizeof(path), "%s/%s/strings/0x409/manufacturer", cfgfs, gname);
    wrstr(path, "Realtek");
    snprintf(path, sizeof(path), "%s/%s/strings/0x409/product", cfgfs, gname);
    wrstr(path, "RTL8812AU");

    /* 4. Configuration */
    snprintf(path, sizeof(path), "%s/%s/configs/c.1/MaxPower", cfgfs, gname);
    wrstr(path, "120");          /* mA */

    /* 5.  Functions */
	snprintf(path, sizeof(path), "%s/%s/functions/ecm.usb0", cfgfs, gname);
	if (lkl_sys_mkdir(path, 0755)) { printf("mkdir gadget functions error"); return; }
	snprintf(path, sizeof(path), "%s/%s/functions/ecm.usb0/host_addr", cfgfs, gname);
    wrstr(path, "02:00:00:00:00:00");
	snprintf(path, sizeof(path), "%s/%s/functions/ecm.usb0/dev_addr", cfgfs, gname);
    wrstr(path, "02:00:00:00:00:01");
	/* Link function into configuration */
    char link_src[256], link_dst[256];
    snprintf(link_src, sizeof(link_src), "%s/%s/functions/ecm.usb0", cfgfs, gname);
    snprintf(link_dst, sizeof(link_dst), "%s/%s/configs/c.1/ecm.usb0", cfgfs, gname);
    lkl_sys_symlink(link_src, link_dst);

    /* 6. Attach gadget to the dummy UDC – device-connect interrupt triggers */
    snprintf(path, sizeof(path), "%s/%s/UDC", cfgfs, gname);
    wrstr(path, "dummy_udc.0");
}

static int initialize_lkl(void)
{
	int ret = lkl_init(&lkl_host_ops);
	if (ret) {
		printf("lkl_init failed\n");
		return -1;
	}

	ret = lkl_start_kernel("mem=4096M kasan.fault=panic loglevel=8");
	if (ret) {
		printf("lkl_start_kernel failed\n");
		lkl_cleanup();
		return -1;
	}
	lkl_mount_fs("sysfs");
	lkl_mount_fs("proc");
	lkl_mount_fs("dev");
	ret = lkl_sys_mount("configfs", "/sysfs/kernel/config", "configfs",
                   0x0, 0x0);
    if (ret < 0) {
	    printf("Failed to mount configfs\n");
	    return -1;
	}
	return 0;
}



void flush_coverage(void)
{
	__llvm_profile_write_file();
}

void end_fuzzing(void) {
	flush_coverage();
	//lkl_sys_halt();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	initialize_lkl();
	load_module(argv[0][argc[0]-2], argv[0][argc[0]-1]);
	load_usb_gadget();
	__llvm_profile_initialize_file();
	atexit(end_fuzzing);

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static int iter;
	uint8_t data[4096] = {0};

	if (Size > 4096)
		Size = 4096;

	memcpy(data, Data, Size);
	fuzz_arbitrary_function(Data, Size);
	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
	}
	return 0;
}

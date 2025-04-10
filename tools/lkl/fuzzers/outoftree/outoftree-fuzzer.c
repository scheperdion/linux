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


static void fuzz_arbitrary_function(const uint8_t *data, size_t size) {
	sleep(1000);
}

static int load_module(char* ko_path, char* arguments) {
//	int fd = open(ko_path, O_RDONLY);
//	int ret = lkl_sys_finit_module(fd, arguments, 0);
//	if(ret != 0) {
//		printf("Error initializing module dependency %s (%d)\n", ko_path, ret);
//		perror("finit_module");
//	}
//	return ret;
     printf("Loading mod dependency %s\n", ko_path);
      void* dep_module_handle = dlopen(ko_path, RTLD_GLOBAL | RTLD_NOW);
      if (!dep_module_handle) {
         printf("Error loading module dependency %s: %s\n", ko_path, dlerror());
         return -1;
      }
      void *this_module_dep = dlsym(dep_module_handle, "__this_module");
      if(!this_module_dep) {
         printf("Error resolving __this_module for %s: %s\n", ko_path, dlerror());
         return -1;
      }
      int err = lkl_sys_init_loaded_module(this_module_dep);
      if(err!=0) {
         printf("Error initializing module dependency %s\n", ko_path);
      }
      return err;
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
	return 0;
}



void flush_coverage(void)
{
	__llvm_profile_write_file();
}

void end_fuzzing(void) {
	flush_coverage();
	lkl_sys_halt();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	initialize_lkl();
	load_module(argv[0][1], argv[0][2]);
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

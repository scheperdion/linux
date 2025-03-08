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

#include "arbitraryfunction-fuzzer.h"

void (*target)(const void *data, size_t datalen);

void set_addresses() {
	void (*src_ptr) = &lkl_init;
	int source_offset = 0x00000000494a50; // nm tools/lkl/fuzzers/arbitraryfunction/arbitraryfunction-fuzzer | grep lkl_init
	int target_offset = 0x00000000beee70; // nm tools/lkl/fuzzers/arbitraryfunction/arbitraryfunction-fuzzer | grep x509_cert_parse
	target = src_ptr - source_offset + target_offset;
}

static void fuzz_arbitrary_function(const uint8_t *data, size_t size) {
	target(data, size);
}

static int initialize_lkl(void)
{
	int ret = lkl_init(&lkl_host_ops);
	if (ret) {
		printf("lkl_init failed\n");
		return -1;
	}

	ret = lkl_start_kernel("mem=4096M kasan.fault=panic loglevel=2");
	if (ret) {
		printf("lkl_start_kernel failed\n");
		lkl_cleanup();
		return -1;
	}
	set_addresses();
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
	__llvm_profile_initialize_file();
	atexit(end_fuzzing);

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static int iter;
	uint8_t data[65535] = {0};

	if (Size > 65535)
		Size = 65535;

	memcpy(data, Data, Size);
	fuzz_arbitrary_function(data, Size);
	iter++;
	if (iter > 1000) {
		flush_coverage();
		iter = 0;
	}
	return 0;
}

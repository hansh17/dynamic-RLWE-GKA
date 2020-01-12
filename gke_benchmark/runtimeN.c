/* This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * See LICENSE for complete information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

#include "../rlwe_kex.h"
#include "clientnserver.h"
#include "../fft.h"
#include "../rlwe.h"
#include "../rlwe_a.h"

#define ITERATIONS 10000

#if defined(__i386__)

uint32_t pub_keys[10][1024];
uint32_t augmented_pub_keys[10][1024];

static __inline__ unsigned long long rdtsc(void) {
	unsigned long long int x;
	__asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
	return x;
}
#elif defined(__x86_64__)

static __inline__ unsigned long long rdtsc(void) {
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ( (unsigned long long)lo) | ( ((unsigned long long)hi) << 32 );
}
#endif

#define START_TIMER \
	gettimeofday(&timeval_start, NULL); \
	cycles_start = rdtsc();
#define END_TIMER \
	cycles_end = rdtsc(); \
	gettimeofday(&timeval_end, NULL);
#define PRINT_TIMER_AVG(op_name, it) \
	printf("%-30s %15d %15d %15" PRIu64 "\n", (op_name), (it), \
		(uint32_t) ((timeval_end.tv_usec+1000000*timeval_end.tv_sec) - (timeval_start.tv_usec+1000000*timeval_start.tv_sec)) / (it), \
		(cycles_end - cycles_start) / (it));
#define TIME_OPERATION(op, op_name, it) \
	START_TIMER \
	for (int i = 0; i < (it); i++) { \
		(op); \
	} \
	END_TIMER \
	PRINT_TIMER_AVG(op_name, it)

int main() {

	uint64_t cycles_start, cycles_end;
	struct timeval timeval_start, timeval_end;

	uint32_t s[1024];
	uint64_t k[16];
	uint64_t c[16];
	unsigned char hk[129];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}

	RAND_CTX rand_ctx;
	if (!RAND_CHOICE_init(&rand_ctx)) {
		printf("Randomness allocation error.");
		return -1;
	}

	printf("%-30s %15s %15s %15s\n", "Operation", "Iterations", "usec (avg)", "cycles (avg)");
	printf("------------------------------------------------------------------------------\n");

	TIME_OPERATION(calculate_pubkey(0, rlwe_a, s, &ctx), "calculate_pub_key", ITERATIONS / 50)
	calculate_pubkey(1, rlwe_a, s, &ctx);
	calculate_pubkey(2, rlwe_a, s, &ctx);
	calculate_pubkey(3, rlwe_a, s, &ctx);
	calculate_pubkey(4, rlwe_a, s, &ctx);
	calculate_pubkey(5, rlwe_a, s, &ctx);
	calculate_pubkey(6, rlwe_a, s, &ctx);
	calculate_pubkey(7, rlwe_a, s, &ctx);

	TIME_OPERATION(calculate_augmented_pubkey(0, 8, s,  &ctx), "calculate_augmented_pub_key0", ITERATIONS / 50)
	calculate_augmented_pubkey(1, 8, s, &ctx);
	calculate_augmented_pubkey(2, 8, s, &ctx);
	calculate_augmented_pubkey(3, 8, s, &ctx);
	calculate_augmented_pubkey(4, 8, s, &ctx);
	calculate_augmented_pubkey(5, 8, s, &ctx);
	calculate_augmented_pubkey(6, 8, s, &ctx);
	calculate_augmented_pubkey(7, 8, s, &ctx);

	TIME_OPERATION(calculate_reconcile(8, s, c, k, hk, &ctx), "calculate_reconcile", ITERATIONS / 50)
	TIME_OPERATION(calculate_session_key(0, 8, s, c, k, hk, &ctx), "calculate_session_key", ITERATIONS / 50)

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

	RAND_CHOICE_cleanup(&rand_ctx);

	return 0;

}
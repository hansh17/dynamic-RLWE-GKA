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
#include "dynamic_test.h"
#include "../fft.h"
#include "../rlwe.h"
#include "../rlwe_a.h"

#define ITERATIONS 10000

#if defined(__i386__)

uint32_t pub_keys[6][1024];
uint32_t augmented_pub_keys[6][1024];

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

	uint32_t *a = rlwe_a;
	uint32_t s[1024];
	uint32_t e[1024];
	uint32_t b[1024];
	uint64_t k[16];
	uint64_t c[16];
	unsigned char hk[129];
	 
	uint32_t s_alice[1024]; 
	uint32_t s_bob[1024];	
	uint32_t s_david[1024];
	uint32_t s_eve[1024];	
	uint64_t rec[16];

	uint64_t k_alice[16];
	uint64_t k_bob[16];	
	uint64_t k_charlie[16];
	uint64_t k_david[16];
	uint64_t k_eve[16];

	static unsigned char hk_alice[129];
	static unsigned char hk_bob[129];
	static unsigned char hk_charlie[129];
	static unsigned char hk_david[129];
	static unsigned char hk_eve[129];

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

#ifdef CONSTANT_TIME
	TIME_OPERATION(rlwe_sample_ct(s, &rand_ctx), "sample_ct", ITERATIONS / 50)
	TIME_OPERATION(FFT_mul(b, a, s, &ctx), "FFT_mul", ITERATIONS / 50)
	TIME_OPERATION(rlwe_sample2_ct(e, &rand_ctx), "sample2_ct", ITERATIONS / 50)
	TIME_OPERATION(FFT_add(b, b, e), "FFT_add", ITERATIONS)
	TIME_OPERATION(rlwe_crossround2_ct(c, b, &rand_ctx), "crossround2_ct", ITERATIONS / 10)
	TIME_OPERATION(rlwe_round2_ct(k, b), "round2_ct", ITERATIONS / 10)
	TIME_OPERATION(rlwe_rec_ct(k, b, c), "rec_ct", ITERATIONS)
#else
	TIME_OPERATION(rlwe_sample(s, &rand_ctx), "sample", ITERATIONS / 50)
	TIME_OPERATION(FFT_mul(b, a, s, &ctx), "FFT_mul", ITERATIONS / 50)
	TIME_OPERATION(rlwe_sample2(e, &rand_ctx), "sample2", ITERATIONS / 50)
	TIME_OPERATION(FFT_add(b, b, e), "FFT_add", ITERATIONS)
	TIME_OPERATION(rlwe_crossround2(c, b, &rand_ctx), "crossround2", ITERATIONS / 10)
	TIME_OPERATION(rlwe_round2(k, b), "round2", ITERATIONS / 10)
	TIME_OPERATION(rlwe_rec(k, b, c), "rec", ITERATIONS)
#endif

	TIME_OPERATION(rlwe_kex_generate_keypair(a, s, b, &ctx), "rlwe_kex_generate_keypair", ITERATIONS / 50)

	TIME_OPERATION(calculate_pubkey(0, a, s_alice, &ctx), "calculate_pub_key", ITERATIONS / 50)
	calculate_pubkey(1, a, s_bob, &ctx);	
	calculate_pubkey(2, a, s_david, &ctx);
	calculate_pubkey(3, a, s_eve, &ctx);		

	TIME_OPERATION(calculate_augmented_pubkey(0,4, s_alice, &ctx), "calculate_augmented_pub_key0", ITERATIONS / 50)
	TIME_OPERATION(calculate_augmented_pubkey(1,4, s_bob, &ctx), "calculate_augmented_pub_key1", ITERATIONS / 50)
	calculate_augmented_pubkey(2,4, s_david, &ctx);
	calculate_augmented_pubkey(3,4, s_eve, &ctx);

	TIME_OPERATION(calculate_reconcile(4, s_eve, rec, k_eve, hk_eve, &ctx), "calculate_reconcile", ITERATIONS / 50)
	TIME_OPERATION(calculate_session_key(0,4, s_alice, rec, k_alice, hk_alice, &ctx), "calculate_session_key", ITERATIONS / 50)
	TIME_OPERATION(calculate_remain_session_key(2, 4, s_bob, rec, k_charlie, hk_charlie, &ctx), "calculate_remain_session_key", ITERATIONS / 50)

	TIME_OPERATION(sha512_session_key(k, hk), "hash_session_key", ITERATIONS / 50)

	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);

	RAND_CHOICE_cleanup(&rand_ctx);

	return 0;

}

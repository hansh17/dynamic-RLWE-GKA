#ifndef _CLIENTNSERVER_H_
#define _CLIENTNSERVER_H_

#include <stdint.h>

#include "../fft.h"

#define MAX_PEER 10
#define POLY_LEN 1024

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);

void sha512_session_key(uint64_t *in, char outputBuffer[129]);

int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);

#endif /* _CLIENTNSERVER_H_ */
	

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../rlwe.h"
#include "../fft.h"
#include "../rlwe_rand.h"
//#include "../rlwe_a.h"
#include "../rlwe_kex.h"

#define _CRT_SECURE_NO_WARNINGS
#define MAX_PEER 10
#define POLY_LEN 1024

uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx) {
	if (peer < 0 || peer > MAX_PEER){
        printf("peer range error!\n");
        return -1;
    }
    
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
#if CONSTANT_TIME
	rlwe_sample_ct(s, &rand_ctx);
	rlwe_sample_ct(e, &rand_ctx);
#else
	rlwe_sample(s, &rand_ctx);
	rlwe_sample(e, &rand_ctx);
#endif
	
	uint32_t tmp[1024];
	rlwe_key_gen(tmp, a, s, e, ctx); // tmp에 as+e 저장
	for(int t=0; t<1024; t++){
		pub_keys[peer][t]=tmp[t];
	}
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx){ 
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}

	uint32_t result[1024]={0,};
	uint32_t tmp1[1024];
	uint32_t tmp2[1024];
	
	if (peer==num_peer-1){	// peer N-1
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);		
#endif	
		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[0][t]; // tmp1=pub_keys[0];
			tmp2[t]=pub_keys[peer-1][t]; // tmp2=pub_keys[peer-1];
		}

		FFT_sub(result, tmp1, tmp2); // z[0]-z[1]
		FFT_mul(result, result, s, ctx); // res*s_eve
		FFT_add(result, result, e);	
	}
	
	else if (peer==0){ // peer 0
#if CONSTANT_TIME
		rlwe_sample2_ct(e, &rand_ctx); // sample from sigma2
#else
		rlwe_sample2(e, &rand_ctx); // sample from sigma2
#endif	
		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t]; // peer=0인 경우 pub_keys[1]
			tmp2[t]=pub_keys[num_peer-1][t]; // pub_keys[N-1]
		}
		
		FFT_sub(result, tmp1, tmp2); // z[1]-z[2]
		FFT_mul(result, result, s, ctx); // res*s_alice
		FFT_add(result, result, e);
	}
	
	else{ // other peers
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx);
#else
		rlwe_sample(e, &rand_ctx);
#endif	

		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t];
			tmp2[t]=pub_keys[peer-1][t];
		}		
		
		FFT_sub(result, tmp1, tmp2); // res=z[2] - z[0]
		FFT_mul(result, result, s, ctx); // res= res* s_bob
		FFT_add(result, result, e); // res= res+e
	}
	
	for(int t=0; t<1024; t++){
		augmented_pub_keys[peer][t]=result[t]; // X[i] save
	}
	
	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp1, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

void sha512_session_key(uint64_t *in, char outputBuffer[129])
{
    unsigned char hash[SHA512_DIGEST_LENGTH]; // 64
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, in, 8*16);
    SHA512_Final(hash, &sha512);
    int i = 0;
    for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[128]=0;
}


int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
	
	uint32_t result[1024]={0,};	
#if CONSTANT_TIME
	rlwe_sample_ct(e, &rand_ctx);
#else
	rlwe_sample(e, &rand_ctx);
#endif	
	
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024];
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[num_peer-2][t]; // tmp=z_N-2
		tmp2[t]=augmented_pub_keys[num_peer-1][t]; // tmp=X_N-1
	}

	FFT_mul(tmp, tmp, s, ctx); // tmp=z_n-2 * s_n-1
	FFT_add(tmp, tmp, tmp2); // tmp=tmp+X_N-1
	FFT_add(tmp, tmp, e); // tmp=tmp+error
	
	for(int k=0; k<1024; k++){
		Y[num_peer-1][k]=tmp[k]; // Y[N-1]=tmp 값
		tmp2[k]=augmented_pub_keys[0][k]; // tmp2=X_0
	}
	
	FFT_add(tmp, tmp, tmp2); // calculate Y[0]
	for(int k=0; k<1024; k++){
		Y[0][k]=tmp[k];
		tmp2[k]=augmented_pub_keys[1][k]; // tmp2=X_1
	}
	
	
	for (int j=1; j<num_peer-1; j++){
		FFT_add(tmp, tmp, tmp2); // calculate Y[j-1] + X[j]
		for(int k=0; k<1024; k++){
			Y[j][k]=tmp[k]; // Y[j]=tmp
			tmp2[k]=augmented_pub_keys[j+1][k]; // tmp2=X_j+1
		}
	}
	
    for (int i = 0; i < num_peer; i++) // calculate b
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp=Y[i]
		}
        FFT_add(result, result, tmp); 
    }

	

#if CONSTANT_TIME // reconcile message b -> rec, k_n-1 is calculated
	rlwe_crossround2_ct(rec, result, &rand_ctx);
	rlwe_round2_ct(k, result);
#else
	rlwe_crossround2(rec, result, &rand_ctx);
	rlwe_round2(k, result);
#endif	
	
	sha512_session_key(k, hk);

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[(peer+num_peer-1)%num_peer][t]; // tmp=z[peer-1]
		tmp2[t]=augmented_pub_keys[peer][t]; // tmp2=X[peer]
	}	
	
	FFT_mul(tmp, tmp, s, ctx); // tmp=z_i-1*s_i 
	FFT_add(tmp, tmp2, tmp); // tmp=X_i+tmp

	for(int t=0; t<1024; t++){
		Y[peer][t]=tmp[t]; // Y[i] 저장 (tmp)
		tmp2[t]=augmented_pub_keys[(peer+1)%num_peer][t]; // tmp2=X[peer+1]
	}
	
	for (int j=1; j<num_peer; j++){
		FFT_add(tmp, tmp, tmp2); // Y[i]=Y[i-1]+X[i]
		for(int t=0; t<1024; t++){
			Y[(peer+j)%num_peer][t]=tmp[t]; // Y[peer+j] 저장 (tmp)
			tmp2[t]=augmented_pub_keys[(peer+j+1)%num_peer][t]; // tmp2=X[peer+j+1]
		}
	}
	
	uint32_t result[1024]={0,};
    for (int i = 0; i < num_peer; i++) // calculate b
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp=Y[i]
		}
        FFT_add(result, result, tmp);
    }

#if CONSTANT_TIME
	rlwe_rec_ct(k, result, rec);
#else
	rlwe_rec(k, result, rec);
#endif

	sha512_session_key(k, hk);

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * 10 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
}

/*
int main(){
	uint32_t *a = rlwe_a; // 'a' is a predefined public rlwe instance
	uint32_t s_alice[1024]; // n=1024
	uint32_t s_bob[1024];
	uint32_t s_eve[1024];
	uint32_t s_david[1024];
	
	uint64_t rec[16];
	
	uint64_t k_alice[16];
	uint64_t k_bob[16];
	uint64_t k_eve[16];
	uint64_t k_david[16];
	static unsigned char hk_alice[129];
	static unsigned char hk_bob[129];
	static unsigned char hk_eve[129];
	static unsigned char hk_david[129];

	FFT_CTX ctx;
	if (!FFT_CTX_init(&ctx)) {
		printf("Memory allocation error.");
		return -1;
	}
	
	
	calculate_pubkey(0, a, s_alice, &ctx); 
	calculate_pubkey(1, a, s_bob, &ctx);
	calculate_pubkey(2, a, s_eve, &ctx);
	calculate_pubkey(3, a, s_david, &ctx);
		
	calculate_augmented_pubkey(0,4, s_alice, &ctx);
	calculate_augmented_pubkey(1,4, s_bob, &ctx);
	calculate_augmented_pubkey(2,4, s_eve, &ctx);
	calculate_augmented_pubkey(3,4, s_david, &ctx);
	
	calculate_reconcile(4, s_david, rec, k_david, hk_david, &ctx);
	
	calculate_session_key(0,4, s_alice, rec, k_alice, hk_alice, &ctx);
	calculate_session_key(1,4, s_bob, rec, k_bob, hk_bob, &ctx);
	calculate_session_key(2,4, s_eve, rec, k_eve, hk_eve, &ctx);

	int keys_match = 1;
	for (int i = 0; i < 16; i++) {
		keys_match &= (k_alice[i] == k_bob[i]);
		keys_match &= (k_eve[i] == k_bob[i]);
		keys_match &= (k_eve[i] == k_alice[i]);
		keys_match &= (k_eve[i] == k_david[i]);
	}
	
	if (keys_match) {
		printf("Keys match.\n");
	} else {
		printf("Keys don't match! :(\n");
		FFT_CTX_free(&ctx);
		return -1;
	}


	int hkeys_match = 1;
	for (int i = 0; i < 129; i++) {
		hkeys_match &= (hk_alice[i] == hk_bob[i]);
		hkeys_match &= (hk_eve[i] == hk_bob[i]);
		hkeys_match &= (hk_eve[i] == hk_alice[i]);
		hkeys_match &= (hk_eve[i] == hk_david[i]);
	}
	
	if (hkeys_match) {
		printf("Hased Keys match.\n");
	} else {
		printf("Hased Keys don't match! :(\n");
		for(int i=0; i<128; i++){
			printf("%02x", hk_alice[i]);
		}
		printf("\n");
		for(int i=0; i<128; i++){
			printf("%02x", hk_bob[i]);
		}
		printf("\n");
		for(int i=0; i<128; i++){
			printf("%02x", hk_eve[i]);
		}
		printf("\n");				
		for(int i=0; i<128; i++){
			printf("%02x", hk_david[i]);
		}
		printf("\n");
		int t = (hk_alice[0]==hk_eve[0]);
		printf("%d\n", t);				
		FFT_CTX_free(&ctx);
		return -1;
	}
	
	FFT_CTX_clear(&ctx);
	FFT_CTX_free(&ctx);
	
	return 0;
}
*/

	

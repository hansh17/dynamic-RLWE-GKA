#include <arpa/inet.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdint.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../rlwe.h"
#include "../fft.h"
#include "../rlwe_rand.h"
#include "../rlwe_kex.h"

#define MAX_PEER 6
#define POLY_LEN 1024
#define KEY_LEN  16
#define HASH_LEN 129

bool check_augmented_pub_keys[MAX_PEER];

bool option_check[4][MAX_PEER];

uint32_t sec_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];
unsigned char hashed_keys[MAX_PEER][HASH_LEN];

uint64_t reconcile[KEY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);
int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);
int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);
void sha512_session_key(uint64_t *in, char outputBuffer[129]);
int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);
int calculate_remain_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);

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

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024], FFT_CTX *ctx){ 
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
	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));
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

	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));

	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));

	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));

	return 1;

}





int calculate_remain_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){

		

	uint32_t Y[MAX_PEER][POLY_LEN];

	uint32_t tmp[1024];

	uint32_t tmp2[1024]; 

	

	for(int t=0; t<1024; t++){

		tmp[t]=pub_keys[2][t]; // tmp=z[peer-1]

		tmp2[t]=augmented_pub_keys[2][t]; // tmp2=X[peer]

	}	

	

	FFT_mul(tmp, tmp, s, ctx); // tmp=z_i-1*s_i 

	FFT_add(tmp, tmp2, tmp); // tmp=X_i+tmp



	for(int t=0; t<1024; t++){

		Y[2][t]=tmp[t]; 

		tmp2[t]=augmented_pub_keys[3][t]; 

	}

	

	for (int j=1; j<num_peer; j++){

		FFT_add(tmp, tmp, tmp2); // Y[i]=Y[i-1]+X[i]

		for(int t=0; t<1024; t++){

			Y[(2+j)%num_peer][t]=tmp[t]; // Y[peer+j] 저장 (tmp)

			tmp2[t]=augmented_pub_keys[(2+j+1)%num_peer][t]; // tmp2=X[peer+j+1]

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

	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));

	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));

	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));

	return 1;

}

#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "fft.h"
#include "rlwe.h"
#include "rlwe_a.h"
#include "rlwe_rand.h"

#define MAX_PEER 6
#define POLY_LEN 1024
#define KEY_LEN  16
#define HASH_LEN 129

uint32_t sec_keys[MAX_PEER][POLY_LEN];
uint32_t pub_keys[MAX_PEER][POLY_LEN];
uint32_t augmented_pub_keys[MAX_PEER][POLY_LEN];
uint64_t session_keys[MAX_PEER][KEY_LEN];
unsigned char hashed_keys[MAX_PEER][HASH_LEN];
uint64_t reconcile[KEY_LEN];

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx);
int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx);
int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);

int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx) // calculate z_i in Round 1 (i=peer)
{
	if (peer < 0 || peer > MAX_PEER)
	{
        		printf("peer range error!\n");
        		return -1;
    	}  
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx); // initialize seed
	if (!ret) 
	{
		return ret;
	}

#if CONSTANT_TIME
	rlwe_sample_ct(s, &rand_ctx); // sample s_i (constant)
	rlwe_sample_ct(e, &rand_ctx); // sample e_i (constant)
#else
	rlwe_sample(s, &rand_ctx); // sample s_i (non-constant)
	rlwe_sample(e, &rand_ctx); // sample e_i (non-constant)
#endif

	uint32_t tmp[1024];
	rlwe_key_gen(tmp, a, s, e, ctx);  // compute tmp=as_i+e_i
	for(int t=0; t<1024; t++)
	{
		pub_keys[peer][t]=tmp[t]; // save tmp as pub_keys[peer]
	}

	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx) // calculate X_i in Round 2 (i=peer)
{
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx); // initialize seed
	if (!ret)
	{
		return ret;
	}

	uint32_t result[1024]={0,};
	uint32_t tmp1[1024];
	uint32_t tmp2[1024];
	if (peer==num_peer-1) // if i = N-1
	{
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx); // sample e'_{N-1} (constant)
#else
		rlwe_sample(e, &rand_ctx); // sample e'_{N-1} (non-constant)	
#endif	
		for(int t=0; t<1024; t++)
		{
			tmp1[t]=pub_keys[0][t]; // tmp1 = z_0
			tmp2[t]=pub_keys[peer-1][t]; // tmp2 = z_{N-2}
		}
		FFT_sub(result, tmp1, tmp2); // result = z_0 - z_{N-2}
		FFT_mul(result, result, s, ctx);  // result = (z_0 - z_{N-2}) * s_{N-1}
		FFT_add(result, result, e); // result = (z_0 - z_{N-2}) * s_{N-1} + e'_{N-1}
	}	
	else if (peer==0) // if i = 0
	{
#if CONSTANT_TIME
		rlwe_sample2_ct(e, &rand_ctx); // sample e'_0 from sigma2 (constant)
#else
		rlwe_sample2(e, &rand_ctx); // sample e'_0 from sigma2 (non-constant)
#endif	
		for(int t=0; t<1024; t++)
		{
			tmp1[t]=pub_keys[peer+1][t]; // tmp1 = z_1
			tmp2[t]=pub_keys[num_peer-1][t]; // tmp2 = z_{N-1}
		}
		FFT_sub(result, tmp1, tmp2); // result = z_1 - z_{N-1}
		FFT_mul(result, result, s, ctx); // result = (z_1 - z_{N-1}) * s_0
		FFT_add(result, result, e); // result = (z_1 - z_{N-1}) * s_0 + e'_0
	}
	else // if 1<= i <= N-2
	{
#if CONSTANT_TIME
		rlwe_sample_ct(e, &rand_ctx); // sample e'_i (constant)
#else
		rlwe_sample(e, &rand_ctx); // sample e'_i (non-constant)
#endif	
		for(int t=0; t<1024; t++)
		{
			tmp1[t]=pub_keys[peer+1][t]; // tmp1= z_{i+1}
			tmp2[t]=pub_keys[peer-1][t]; // tmp2 = z_{i-1}
		}		
		FFT_sub(result, tmp1, tmp2); // result = z_{i+1} - z_{i-1} 
		FFT_mul(result, result, s, ctx); // result = (z_{i+1} - z_{i-1}) * s_i
		FFT_add(result, result, e); // result = (z_{i+1} - z_{i-1}) * s_i + e'_i
	}

	for(int t=0; t<1024; t++)
	{
		augmented_pub_keys[peer][t]=result[t]; // save result as augmented_pub_keys[peer]
	}

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp1, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

void sha512_session_key(uint64_t *in, char outputBuffer[129]) // calculate hash value of session key (SHA-512)
{
    unsigned char hash[SHA512_DIGEST_LENGTH]; // SHA512_DIGEST_LENGTH=64
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

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx) // compute sk_i
{		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 

	for(int t=0; t<1024; t++)
	{
		tmp[t]=pub_keys[(peer+num_peer-1)%num_peer][t]; // tmp = z_{i-1} (peer=i)
		tmp2[t]=augmented_pub_keys[peer][t];  // tmp2 = X_i
	}	
	
	FFT_mul(tmp, tmp, s, ctx); // tmp = z_{i-1} * s_i 
	FFT_add(tmp, tmp2, tmp); // tmp = X_i + z_{i-1} * s_i 

	for(int t=0; t<1024; t++)
	{
		Y[peer][t]=tmp[t]; // save tmp as Y_i
		tmp2[t]=augmented_pub_keys[(peer+1)%num_peer][t]; // tmp2 = X_{i+1}
	}
	for (int j=1; j<num_peer; j++)
	{
		FFT_add(tmp, tmp, tmp2); // tmp = Y_{i+j-1} + X_{i+j}
		for(int t=0; t<1024; t++)
		{
			Y[(peer+j)%num_peer][t]=tmp[t]; // save tmp as Y_{i+j}
			tmp2[t]=augmented_pub_keys[(peer+j+1)%num_peer][t]; // tmp2 = X_{i+j+1}
		}
	}
	
	uint32_t result[1024]={0,};
    	for (int i = 0; i < num_peer; i++) // compute b_i
   	{
		for(int k=0; k<1024; k++)
		{
			tmp[k]=Y[i][k]; // tmp = Y_i
		}
        		FFT_add(result, result, tmp); // result = result + Y_i
    	}
#if CONSTANT_TIME
	rlwe_rec_ct(k, result, rec); // compute key k_i (constant)
#else
	rlwe_rec(k, result, rec); // compute key k_i (non-constant)
#endif
	sha512_session_key(k, hk); // compute hash value of k_i and save as hk_i

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
}

int main(int argc, char *argv[])
{
    int client_socket;
    client_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (client_socket == -1)
    {
        printf("socket() error!\n");
        exit(1);
    }

    char *server_ip = "127.0.0.1";
    int server_port = 4000;
    char op;
    int option = -1;
    int peer = -1;
    bool first_process;
    int num_peer = 3;
    FFT_CTX ctx;
    FFT_CTX_init(&ctx);

    while ((op = getopt(argc, argv, "h:p:o:w:")) != -1)
    {
        switch (op)
        {
            case 'h':
                server_ip   = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'o':
                option      = atoi(optarg);
                break;
            case 'w':
                peer        = atoi(optarg);
                break;
        }
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("connect() error!\n");
        exit(1);
    }

    while (true)
    {
        send(client_socket, &peer, sizeof(peer), 0);
        recv(client_socket, &option, sizeof(option), 0);
        recv(client_socket, &first_process, sizeof(first_process), 0);

        if (!first_process)
            continue;
        if (option > 3)
            break;

        switch (option)
        {
            case 0:
            {
                calculate_pubkey(peer, rlwe_a, sec_keys[peer], &ctx); // compute z_i
                send(client_socket, pub_keys[peer], sizeof(pub_keys[peer]), 0); // send z_i
                break;
            }
            case 1:
            {
                recv(client_socket, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0); // receive z
                calculate_augmented_pubkey(peer, num_peer, sec_keys[peer], &ctx); // compute X_i
                send(client_socket, augmented_pub_keys[peer], sizeof(augmented_pub_keys[peer]), 0); // send X_i
                break;
            }
            case 2:
            {
                recv(client_socket, augmented_pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0); // receive X
                break;
            }
            case 3:
            {
                recv(client_socket, reconcile, sizeof(reconcile), 0); // receive rec
                uint64_t result[KEY_LEN];
	   unsigned char hashed_result[HASH_LEN];
                calculate_session_key(peer, num_peer, sec_keys[peer], reconcile, result, hashed_result, &ctx); // compute sk_i
	    send(client_socket, hashed_result, sizeof(hashed_result), 0); // send sk_i

                printf("Peer %d hashed key : ", peer); // print sk_i
		        for (int i = 0; i < 129; i++)
                    printf("%c", hashed_result[i]);
                printf("\n");
                break;
            }
            default:
            {
                printf("unknown option!\n");
                break;
            }
        }
    }
    close(client_socket);
    return 0;
}

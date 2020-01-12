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
#include "fft.h"
#include "rlwe.h"
#include "rlwe_a.h"
#include "rlwe_rand.h"

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
void run_server(int num_peer, int server_port);

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

int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){ // calculate reconcile
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx); // initialize seed
	if (!ret)
	{
		return ret;
	}
	
#if CONSTANT_TIME
	rlwe_sample_ct(e, &rand_ctx); // sample e''_{N-1} (constant)
#else
	rlwe_sample(e, &rand_ctx); // sample e''_{N-1} (non-constant)
#endif	

	uint32_t Y[MAX_PEER][POLY_LEN]; 
	uint32_t tmp[1024];
	uint32_t tmp2[1024];
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[num_peer-2][t]; // tmp = z_{N-2}
		tmp2[t]=augmented_pub_keys[num_peer-1][t]; // tmp2 = X_{N-1}
	}

	FFT_mul(tmp, tmp, s, ctx); // tmp = z_{N-2} * s_{N-1}
	FFT_add(tmp, tmp, tmp2); // tmp = z_{N-2} * s_{N-1} + X_{N-1}
	FFT_add(tmp, tmp, e); // tmp = z_{N-2} * s_{N-1} + X_{N-1} + e''_{N-1}
	
	for(int k=0; k<1024; k++){
		Y[num_peer-1][k]=tmp[k]; // save tmp as Y_{N-1}
		tmp2[k]=augmented_pub_keys[0][k]; // tmp2 = X_0
	}
	
	FFT_add(tmp, tmp, tmp2); // tmp = Y_{N-1} + X_0
	for(int k=0; k<1024; k++){
		Y[0][k]=tmp[k]; // save tmp as Y_0
		tmp2[k]=augmented_pub_keys[1][k]; // tmp2 = X_1 
	}
	for (int j=1; j<num_peer-1; j++){
		FFT_add(tmp, tmp, tmp2); // tmp = Y_{j-1} + X_j 
		for(int k=0; k<1024; k++){
			Y[j][k]=tmp[k]; // save tmp as Y_j
			tmp2[k]=augmented_pub_keys[j+1][k]; // tmp2 = X_{j+1}
		}
	}
	
	uint32_t result[1024]={0,};		
    	for (int i = 0; i < num_peer; i++) // compute b_{N-1}
    	{
		for(int k=0; k<1024; k++)
		{
			tmp[k]=Y[i][k]; // tmp = Y_i 
		}
        		FFT_add(result, result, tmp); // result = result + Y_i
    	}

#if CONSTANT_TIME 
	rlwe_crossround2_ct(rec, result, &rand_ctx); // compute rec (constant)
	rlwe_round2_ct(k, result); // compute key k_{N-1} (constant)
#else
	rlwe_crossround2(rec, result, &rand_ctx); // compute rec (non-constant)
	rlwe_round2(k, result); // compute key k_{N-1} (non-constant)
#endif	
	sha512_session_key(k, hk); // compute hash value of k_{N-1} and save as hk_{N-1}

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int next_option(int option, int num_peer) // To check whether (step i) finish or not
{
    bool check = true;
    for (int i = 0; i < num_peer - 1; i++)
    {
        check = check && option_check[option][i];
    }
    if (check)
        return option + 1;
    return option;
}

void run_server(int num_peer, int server_port) // Communication between peers and arbiter
{
    int server_socket;
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        printf("socket() error!\n");
        exit(1);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("bind() error!\n");
        exit(1);
    }
    if (listen(server_socket, 5) == -1)
    {
        printf("listen() error!\n");
        exit(1);
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_size;
    client_addr_size = sizeof(client_addr);
    int client_socket[MAX_PEER];
    for (int i = 0; i < num_peer; i++)
    {
        client_socket[i] = 0;
    }
    fd_set readfds;
    int sd, max_sd;
    int activity;
    int new_socket;
    int peer;
    int option = 0;
    bool first_process;
    uint32_t result[POLY_LEN];

    memset(check_augmented_pub_keys, false, sizeof(check_augmented_pub_keys));
    memset(option_check, false, sizeof(option_check));
    bool reconcile_calculated = false;
    FFT_CTX ctx;
    FFT_CTX_init(&ctx);
    calculate_pubkey(num_peer - 1, rlwe_a, sec_keys[num_peer - 1], &ctx); // calculate z_{N-1}

    while (option < 4)
    {
        FD_ZERO(&readfds);
        FD_SET(server_socket, &readfds);
        max_sd = server_socket;

        for (int i = 0; i < num_peer-1; i++)
        {
            sd = client_socket[i];
            if (sd > 0)
                FD_SET(sd, &readfds);
            if (sd > max_sd)
                max_sd = sd;
        }
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (FD_ISSET(server_socket, &readfds)) // peer and arbiter connect
        {
            new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
            for (int i = 0; i < num_peer-1; i++)
            {
                if (client_socket[i] == 0)
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }

        for (int p = 0; p < num_peer-1; p++)
        {
            sd = client_socket[p];

            if (FD_ISSET(sd, &readfds))
            {
                recv(sd, &peer, sizeof(peer), 0);
                if (!(0 <= peer && peer < num_peer))
                {
                    printf("peer number error\n");
                    close(sd);
                    continue;
                }

                if (!reconcile_calculated) // if rec is not computed
                {
                    bool all_augmented_pub_keys = true;
                    for (int i = 0; i < num_peer; i++)
                    {
                        if (!check_augmented_pub_keys[i])
                        {
                            all_augmented_pub_keys = false;
                            break;
                        }
                    }
                    if (all_augmented_pub_keys) // if receive all X_i (0<=i<=N-2)
                    {
                        calculate_reconcile(num_peer, sec_keys[num_peer - 1], reconcile, session_keys[num_peer - 1], hashed_keys[num_peer-1], &ctx);
                        reconcile_calculated = true;
                    }
                }

                send(sd, &option, sizeof(option), 0); // send step i (i=option)

                if (option == 1) // if step 0 is done, compute X_{N-1}
                {
                    calculate_augmented_pubkey(num_peer - 1, num_peer, sec_keys[num_peer - 1], &ctx);
                    check_augmented_pub_keys[num_peer - 1] = true;
                }

                first_process = !option_check[option][peer];
                send(sd, &first_process, sizeof(first_process), 0);

                if (!first_process)
                    continue;

                switch (option)
                {
                    case 0:
                    {
                        recv(sd, pub_keys[peer], POLY_LEN * sizeof(uint32_t), 0); // receive z_i
                        printf("option 0 clear with peer %d!\n", peer);
                        break;
                    }
                    case 1:
                    {
                        send(sd, pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0); // broadcast z
                        recv(sd, result, sizeof(result), 0); // receive X_i
                        memcpy(augmented_pub_keys[peer], result, sizeof(augmented_pub_keys[peer]));
                        check_augmented_pub_keys[peer] = true;
                        printf("option 1 clear with peer %d!\n", peer);
                        break;
                    }
                    case 2:
                    {
                        send(sd, augmented_pub_keys, sizeof(uint32_t) * num_peer * POLY_LEN, 0); // broadcast X
                        printf("option 2 clear with peer %d!\n", peer);
                        break;
                    }
                    case 3:
                    {
                        send(sd, reconcile, sizeof(reconcile), 0); // broadcast rec
	            recv(sd, hashed_keys[peer], sizeof(hashed_keys[peer]), 0); // receive sk_i
                        printf("option 3 clear with peer %d!\n", peer);
                    }
                }
                option_check[option][peer] = true;
                option = next_option(option, num_peer); // if communication with all peers is done, go to next step
            }
        }
    }

    printf("Arbiter hashed key : "); // print sk_{N-1}
    for (int i = 0; i < 129; i++)
        printf("%c", hashed_keys[num_peer - 1][i]); 
    printf("\n");
}

int main(int argc, char *argv[])
{
    int num_peer = 3; // N=3
    int server_port = 4000; // default port = 4000
    char op;

    while ((op = getopt(argc, argv, "p:")) != -1)
    {
        switch (op)
        {
            case 'p':
                server_port = atoi(optarg);
                break;
        }
    }

    run_server(num_peer, server_port);
    return 0;
}

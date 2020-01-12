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
int calculate_remain_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx);


int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx) { // z_{peer} 계산 (Round 1)
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
	rlwe_sample(s, &rand_ctx); // Gaussian 분포(sigma1)에서 랜덤 샘플링 후 s에 저장
	rlwe_sample(e, &rand_ctx); // Gaussian 분포(sigma1)에서 랜덤 샘플링 후 e에 저장
	
	uint32_t tmp[1024];
	rlwe_key_gen(tmp, a, s, e, ctx); // as+e 계산 후 tmp에 저장
	for(int t=0; t<1024; t++){
		pub_keys[peer][t]=tmp[t]; // pub_keys[peer](=z_{peer})에 tmp값 (as+e) 저장
	} 
	// 메모리 초기화
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx); 
	return ret;
}

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx){ // X_{peer} 계산 (Round 2)
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
	
	if (peer==num_peer-1){	// peer {N-1}의 경우
		rlwe_sample(e, &rand_ctx); // Gaussian 분포(sigma1)에서 랜덤 샘플링 후 e에 저장	

		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[0][t]; // tmp1에 z_0값 저장
			tmp2[t]=pub_keys[peer-1][t]; // tmp2에 z_{N-2}값 저장 
		}

		FFT_sub(result, tmp1, tmp2); // z_0-z_{N-2} 계산 (result에 저장됨)
		FFT_mul(result, result, s, ctx); // (z_0-z_{N-2}) * s_{N-1} 계산 (result에 저장됨)
		FFT_add(result, result, e);	// (z_0-z_{N-2}) * s_{N-1} + e'_{N-1} 계산 (result에 저장됨)
	}
	
	else if (peer==0){ // peer 0의 경우
		rlwe_sample(e, &rand_ctx); // Gaussian 분포(sigma2)에서 랜덤 샘플링 후 e에 저장, 현재는 sigma1에서 샘플링함

		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t]; // tmp1에 z_1값 저장
			tmp2[t]=pub_keys[num_peer-1][t]; // tmp2에 z_{N-1}값 저장
		}
		
		FFT_sub(result, tmp1, tmp2); // z_1-z_{N-1} 계산 (result에 저장됨)
		FFT_mul(result, result, s, ctx); // (z_1-z_{N-1}) * s_0 계산 (result에 저장됨)
		FFT_add(result, result, e); // (z_1-z_{N-1}) * s_0 + e'_0 계산 (result에 저장됨)
	}
	
	else{ // peer 1~{N-2}의 경우 (peer=i라고 하자)
		rlwe_sample(e, &rand_ctx);

		for(int t=0; t<1024; t++){
			tmp1[t]=pub_keys[peer+1][t]; // tmp1에 z_{i+1}값 저장
			tmp2[t]=pub_keys[peer-1][t]; // tmp2에 z_{i-1}값 저장
		}		
		
		FFT_sub(result, tmp1, tmp2); // z_{i+1}-z_{i-1} 계산 (result에 저장됨)
		FFT_mul(result, result, s, ctx); // (z_{i+1}-z_{i-1}) * s_i 계산 (result에 저장됨)
		FFT_add(result, result, e); // (z_{i+1}-z_{i-1}) * s_i + e'_i 계산 (result에 저장됨)
	}
	
	for(int t=0; t<1024; t++){
		augmented_pub_keys[peer][t]=result[t]; // augmented_pub_keys[peer](=X_{peer})에 result값 저장
	}
	//메모리 초기화
	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp1, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

void sha512_session_key(uint64_t *in, char outputBuffer[129]) // sha512로 session key 해쉬
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

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){ // session key 계산 (Key Computation)
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	// 편의상 peer=i로 두자
	for(int t=0; t<1024; t++){ 
		tmp[t]=pub_keys[(peer+num_peer-1)%num_peer][t]; // tmp에 z_{i-1} 저장
		tmp2[t]=augmented_pub_keys[peer][t]; // tmp2에 X_i 저장
	}	
	
	FFT_mul(tmp, tmp, s, ctx); // z_{i-1} * s_i 계산 (tmp에 저장됨) 
	FFT_add(tmp, tmp2, tmp); // X_i + z_{i-1} * s_i 계산 (tmp에 저장됨)

	for(int t=0; t<1024; t++){
		Y[peer][t]=tmp[t]; // Y_i 에 tmp값 저장
		tmp2[t]=augmented_pub_keys[(peer+1)%num_peer][t]; // tmp2에 X_{i+1} 저장
	}
	
	for (int j=1; j<num_peer; j++){
		FFT_add(tmp, tmp, tmp2); // Y_{i+j-1}+X_{i+j} 계산 (tmp에 저장됨)
		for(int t=0; t<1024; t++){
			Y[(peer+j)%num_peer][t]=tmp[t]; // Y_{i+j}에 tmp값 저장
			tmp2[t]=augmented_pub_keys[(peer+j+1)%num_peer][t]; // tmp2에 X_{i+j+1} 저장
		}
	}
	
	uint32_t result[1024]={0,};
    for (int i = 0; i < num_peer; i++) // b 계산
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp에 Y_i 저장
		}
        FFT_add(result, result, tmp); // result = result + tmp (= Y_i)
    }


	rlwe_rec(k, result, rec); // result와 rec 값으로 k 계산
	sha512_session_key(k, hk); // k의 hash 계산 후 hk에 저장
	// 메모리 초기화
	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	return 1;
}


int calculate_remain_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){ // session key 계산 (Key Computation) for join algorithm (peer 2~{N-2}의 경우)
		
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024]; 
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[2][t]; // tmp에 z_2 저장
		tmp2[t]=augmented_pub_keys[2][t]; // tmp2에 X_2 저장
	}	
	
	FFT_mul(tmp, tmp, s, ctx); // z_2 * s_1 계산 (tmp에 저장됨) 
	FFT_add(tmp, tmp2, tmp); //  X_2 + z_2 * s_1 계산 (tmp에 저장됨)

	for(int t=0; t<1024; t++){
		Y[2][t]=tmp[t]; // Y_2 에 tmp값 저장
		tmp2[t]=augmented_pub_keys[3][t]; // tmp2에 X_3 저장
	}
	
	for (int j=1; j<num_peer; j++){
		FFT_add(tmp, tmp, tmp2); // Y_{2+j-1}+X_{2+j} 계산 (tmp에 저장됨)
		for(int t=0; t<1024; t++){
			Y[(2+j)%num_peer][t]=tmp[t]; // Y_{2+j}에 tmp값 저장
			tmp2[t]=augmented_pub_keys[(2+j+1)%num_peer][t]; // tmp2에 X_{2+j+1} 저장
		}
	}
	
	uint32_t result[1024]={0,};
    	for (int i = 0; i < num_peer; i++) // b 계산
    	{
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k];  // tmp에 Y_i 저장
		}
        FFT_add(result, result, tmp); // result = result + tmp (= Y_i)
    	}

	rlwe_rec(k, result, rec); // result와 rec 값으로 k 계산
	sha512_session_key(k, hk); // k의 hash 계산 후 hk에 저장
	// 메모리 초기화
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

    struct sockaddr_in server_addr;
    char *server_ip = "127.0.0.1";
    int server_port = 4000;
    char op;
    int option = -1;
    int peer = -1;

    bool first_process;

    int num_peer2 = 3; // 사람 수 after membership change
    int num_peer = 3; // 사람 수 before membership change
    int stug_index; // STUG 돌리는 사람 수 (join의 경우 M(추가된 멤버 수)+3)
    char *mode="static"; // mode (static, join, leave)

    while ((op = getopt(argc, argv, "h:p:o:w:m:a:b:")) != -1)
    {
        switch (op)
        {
            case 'h': // server ip
                server_ip   = optarg;
                break;
            case 'p': // port
                server_port = atoi(optarg);
                break;
            case 'o':
                option      = atoi(optarg);
                break;
            case 'w': // peer index
                peer        = atoi(optarg);
                break;
            case 'm': // mode
                mode       = optarg;
                break;
            case 'a': // after membership change
                num_peer2      = atoi(optarg);
                break;
            case 'b': // before membership change
                num_peer        = atoi(optarg);
                break;	    
        }
    }

    if (strcmp("join", mode) == 0){
	stug_index=num_peer2-num_peer+3; // M+3
    }
    else if (strcmp("leave", mode) == 0){
	stug_index=num_peer2;
    }
    else{
	stug_index=num_peer2;
    }

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("connect() error!\n");
        exit(1);
    }
    
    int peer_index=-1;
    if (strcmp("join", mode) == 0) //join
    {   

	if (peer==0)
	{
		peer_index=0;
	}
	else if (peer==1)
	{
		peer_index=1;
	}
 	else if (peer==num_peer-1) // join에서 peer N-1의 경우 STUG에서 index 2로 배정됨 
	{
    		peer_index=2;
	}
	else if (num_peer<=peer<num_peer2) // join에서 peer N+j의 경우 STUG에서 index 3+j로 배정됨
	{
		peer_index=3+peer-num_peer;
	}
    }
    else { // leave, static
	peer_index=peer; 
    }

    if (strcmp("join", mode) == 0) // mode가 join일 경우
    {
    while (true)
    {
        send(client_socket, &peer, sizeof(peer), 0);
        recv(client_socket, &option, sizeof(option), 0); // option 값 전달 받음

        recv(client_socket, &first_process, sizeof(first_process), 0);
        if (!first_process)
            continue;

        if (option > 3)
            break;

        switch (option)
        {
            case 0: // case 0에서 z_i 계산 (i는 peer index) 후 arbiter에게 전달
            {
		if (2<=peer && peer<num_peer-1) // peer 2~{N-1}까지는 case 0에서 아무것도 안함
		{
			break;
		} // STUG에 참여하는 peer들은 z_{peer_index}값 계산 후 arbiter에게 전달		
                calculate_pubkey(peer_index, rlwe_a, sec_keys[peer_index], &ctx);
                send(client_socket, pub_keys[peer_index], sizeof(pub_keys[peer_index]), 0);

		if (peer==1) // peer 1은 arbiter에게 secrect key s_1 전달 (session key로 대체?)
		{
			send(client_socket, sec_keys[peer], sizeof(sec_keys[peer]), 0);
		}
                break;
            }
            case 1: // case 1에서 z(모든 z_i의 concatenation) 수신 후 X_i 계산 후 arbiter에게 전달
            {
                recv(client_socket, pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0); // z 수신
		if (2<=peer && peer<num_peer-1) // peer 2~{N-1}까지는 case 1에서 아무것도 안함
		{
			break;
		} // STUG에 참여하는 peer들은 X_{peer_index}값 계산 후 arbiter에게 전달
                calculate_augmented_pubkey(peer_index, stug_index, sec_keys[peer_index], &ctx);
                send(client_socket, augmented_pub_keys[peer_index], sizeof(augmented_pub_keys[peer_index]), 0);
                break;
            }
            case 2: // case 2에서 X (모든 X_i의 concatenation) 수신
            {
                recv(client_socket, augmented_pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0);
                break;
            }
            case 3: // case 3에서 reconcile 수신 후 session key 계산
            {
                recv(client_socket, reconcile, sizeof(reconcile), 0); // reconcile 수신

                uint64_t result[KEY_LEN];
		unsigned char hashed_result[HASH_LEN];
		if (2<=peer && peer<num_peer-1) // peer 2~{N-2}까지는 s_1 수신 후 session key 계산 (s_1 -> session key?)
		{
			recv(client_socket, sec_keys[1], sizeof(uint32_t) * POLY_LEN, 0);
			calculate_remain_session_key(peer, stug_index, sec_keys[1], reconcile, result, hashed_result, &ctx);
		}		
		else // STUG에 참여했던 peer들은 STUG 상에서 session key 계산
		{
                	calculate_session_key(peer_index, stug_index, sec_keys[peer_index], reconcile, result, hashed_result, &ctx);
 		}
		send(client_socket, hashed_result, sizeof(hashed_result), 0); // session key sk_i를 arbiter에게 전송

                printf("Peer %d hashed key : ", peer); // session key 값 출력
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
    }
    else // mode가 leave, static일 경우
    {
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
            case 0: // case 0에서 z_i (i=peer) 계산 후 arbiter에게 전달
            {
                calculate_pubkey(peer, rlwe_a, sec_keys[peer], &ctx);
                send(client_socket, pub_keys[peer], sizeof(pub_keys[peer]), 0);
                break;
            }
            case 1: // case 1에서 z 수신 후 X_i 계산하여 arbiter에게 전달
            {
                recv(client_socket, pub_keys, sizeof(uint32_t) * num_peer2 * POLY_LEN, 0);
                calculate_augmented_pubkey(peer, num_peer2, sec_keys[peer], &ctx);
                send(client_socket, augmented_pub_keys[peer], sizeof(augmented_pub_keys[peer]), 0);
                break;
            }
            case 2: // case 2에서 X 수신
            {
                recv(client_socket, augmented_pub_keys, sizeof(uint32_t) * num_peer2 * POLY_LEN, 0);
                break;
            }
            case 3: // case 3에서 reconcile 수신 후 session key 계산
            {
                recv(client_socket, reconcile, sizeof(reconcile), 0); // reconcile 수신

                uint64_t result[KEY_LEN];
		unsigned char hashed_result[HASH_LEN];
                calculate_session_key(peer, num_peer2, sec_keys[peer], reconcile, result, hashed_result, &ctx); // reconcile를 통해 session key sk_i 계산
		send(client_socket, hashed_result, sizeof(hashed_result), 0); // arbiter에게 sk_i 전달

                printf("Peer %d hashed key : ", peer); // session key 값 출력
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
    }

    close(client_socket);
    return 0;
}

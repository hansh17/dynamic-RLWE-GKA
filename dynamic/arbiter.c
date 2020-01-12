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
void run_server(int num_peer2, int num_peer, int server_port, char* mode);

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

int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], unsigned char hk[129], FFT_CTX *ctx){
	int ret;
	uint32_t e[1024];
	RAND_CTX rand_ctx;
	ret = RAND_CHOICE_init(&rand_ctx);
	if (!ret) {
		return ret;
	}
	
	uint32_t result[1024]={0,};	

	rlwe_sample(e, &rand_ctx); // Gaussian 분포(sigma1)에서 랜덤 샘플링 후 e에 저장 	
	
	uint32_t Y[MAX_PEER][POLY_LEN];
	uint32_t tmp[1024];
	uint32_t tmp2[1024];
	
	for(int t=0; t<1024; t++){
		tmp[t]=pub_keys[num_peer-2][t]; // tmp에 z_{N-2} 저장
		tmp2[t]=augmented_pub_keys[num_peer-1][t]; // tmp2에 X_{N-1} 저장
	}

	FFT_mul(tmp, tmp, s, ctx); // z_{N-2} * s_{N-1} 계산 (tmp에 저장됨) 
	FFT_add(tmp, tmp, tmp2); // X_{N-1} + z_{N-2} * s_{N-1} 계산 (tmp에 저장됨)
	FFT_add(tmp, tmp, e); // X_{N-1} + z_{N-2} * s_{N-1} + e''_{N-1} 계산 (tmp에 저장됨)
	
	for(int k=0; k<1024; k++){
		Y[num_peer-1][k]=tmp[k]; // Y_{N-1}에 tmp값 저장
		tmp2[k]=augmented_pub_keys[0][k]; // tmp2에 X_0 저장
	}
	
	FFT_add(tmp, tmp, tmp2); // Y_{N-1}+X_0 계산 (tmp에 저장됨)
	for(int k=0; k<1024; k++){
		Y[0][k]=tmp[k]; // Y_0에 tmp값 저장
		tmp2[k]=augmented_pub_keys[1][k]; // tmp2에 X_1 저장
	}
	
	
	for (int j=1; j<num_peer-1; j++){
		FFT_add(tmp, tmp, tmp2); // Y_{j-1}+X_j 계산 (tmp에 저장됨)
		for(int k=0; k<1024; k++){
			Y[j][k]=tmp[k]; // Y_j에 tmp값 저장
			tmp2[k]=augmented_pub_keys[j+1][k]; // tmp2에 X_{j+1} 저장
		}
	}
	
    for (int i = 0; i < num_peer; i++) // b 계산
    {
		for(int k=0; k<1024; k++){
			tmp[k]=Y[i][k]; // tmp에 Y_i 저장
		}
        FFT_add(result, result, tmp); // result = result + tmp (= Y_i)
    }

	rlwe_crossround2(rec, result, &rand_ctx); // reconcile result(=b) -> rec와 k_{n-1}이 계산된다.
	rlwe_round2(k, result);
	sha512_session_key(k, hk); // k의 hash 계산 후 hk에 저장 

	rlwe_memset_volatile(result, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(e, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(Y, 0, 1024 * MAX_PEER * sizeof(uint32_t));
	rlwe_memset_volatile(tmp, 0, 1024 * sizeof(uint32_t));
	rlwe_memset_volatile(tmp2, 0, 1024 * sizeof(uint32_t));
	RAND_CHOICE_cleanup(&rand_ctx);
	return ret;
}

int next_option(int option, int num_peer) // 모든 피어에 대해 option (case 0,1,2,3)이 완료되었는지 체크하는 함수
{
    bool check = true;
    for (int i = 0; i < num_peer - 1; i++)
    {
        check = check && option_check[option][i];
    }
    if (check) // 모든 peer에 대해 option이 true면 다음 option으로 넘어감
        return option + 1;
    return option;
}

void run_server(int num_peer2, int num_peer, int server_port, char* mode) // num_peer2 = N+M, num_peer = N, mode=join, leave, static
{
    int server_socket;
    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        printf("socket() error!\n");
        exit(1);
    }

    struct sockaddr_in server_addr; // 서벗 소켓 생성 및 설정
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(server_port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        printf("bind() error!\n");
        exit(1);
    }

    if (listen(server_socket, 5) == -1) // 서버 소켓 listen
    {
        printf("listen() error!\n");
        exit(1);
    }

    int new_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_size;
    
    uint32_t result[POLY_LEN];
    int peer;

    memset(check_augmented_pub_keys, false, sizeof(check_augmented_pub_keys));
    memset(option_check, false, sizeof(option_check));
    bool reconcile_calculated = false;

    FFT_CTX ctx;
    FFT_CTX_init(&ctx);

    int stug_index;   // stug를 돌리는 사람 수
    int index[num_peer2]; // 전체 피어들 STUG에 참여할 때 index 저장
 

    if (strcmp("join", mode) == 0){ //join
    	stug_index=num_peer2-num_peer+3; // 총 멤버 (N+M) - 기존 멤버 (N) + 3
    	index[0]=0; 
    	index[1]=1;
    	index[num_peer-1]=2; // peer {N-1}은 STUG에서 index가 2
    	for(int i=0; i<num_peer2-num_peer; i++)
	{
    		index[num_peer+i]=3+i; // 새로 조인한 피어들은 STUG에서 index가 N+i -> 3+i가 됨    
    	}
	for(int j=2; j<num_peer-1; j++)
	{
		index[j]=-1; // peer 2~{N-2}까지는 STUG 참여 안하므로 index를 -1로 설정
	}
    }
    else{ // static, leave	
    	stug_index=num_peer2; 
    	// save index who participate in STUG
    	for(int i=0; i<num_peer2; i++)
    	{
		index[i]=i; // 모두가 STUG에 참여하므로 peer number와 STUGindex가 동일함
    	}
    }
	
    calculate_pubkey(stug_index - 1, rlwe_a, sec_keys[stug_index-1], &ctx); // STUG에서 마지막 index를 가진 노드가 arbiter 역할을 한다.arbiter의 public key 계산

    int client_socket[MAX_PEER];
    for (int i = 0; i < num_peer2-1; i++)
    {
        client_socket[i] = 0; // 전체 피어 수(N+M)-1개만큼의 client socket 생성 예정 (arbiter는 제외하므로)
    }

    client_addr_size = sizeof(client_addr);

    fd_set readfds;
    int sd, max_sd;
    int activity; // activity는 실제로 사용되지 않음.

    int option = 0; // option은 step과 유사한 개념이라고 보면 됨

    bool first_process;
    while (option < 4) // option이 4로 넘어가면 종료. 모든 클라이언트와 통신을 완료할 때까지 (혹은 에러가 날때까지) 계속 while문 실행
    {
        FD_ZERO(&readfds); // while문 시작할때마다 (fd_set으로 선언된) readfds를 0으로 initialize

        FD_SET(server_socket, &readfds); // readfds에 server_socket을 1로 설정. 
        max_sd = server_socket; // 가장 큰 sd가 현재는 server_socket

        for (int i = 0; i < num_peer2-1; i++) 
        {
            sd = client_socket[i];

            if (sd > 0) 
                FD_SET(sd, &readfds); // client_socket[i]에 값이 있을 시 그 sd값을 1로 설정

            if (sd > max_sd) // 제일 큰 fd값 지정 -> max_sd까지 검사하기 위해서.
                max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL); // max_sd+1 '미만'의 값에 대해 sd이 1인 것들에 대해 이벤트가 발생할 때까지 대기함.

        if (FD_ISSET(server_socket, &readfds)) // *server_socket에 이벤트가 발생했거나, 발생해야함
        {
            new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size); // client 연결 요청 수락

            for (int i = 0; i < num_peer2-1; i++)
            {
                if (client_socket[i] == 0) // 순서대로 new_socket값 배정, i를 증가시켜가면서 검사
                {
                    client_socket[i] = new_socket;
                    break;
                }
            }
        }
	// peer 0~N-1까지 '차례'대로 소켓으로 data 주고 받기. 끝나면 while문으로 이동.
        for (int p = 0; p < num_peer2-1; p++)
        {
            sd = client_socket[p];
            if (FD_ISSET(sd, &readfds)) // sd 소켓에 이벤트가 발생해야함 (통신), 읽기값이 들어오면 활성화됨.
            {
                recv(sd, &peer, sizeof(peer), 0); // peer의 index 수신 (i라고 하자)

                if (!(0 <= peer && peer < num_peer2))
                {
                    printf("peer number error\n");
                    close(sd);
                    continue;
                }

                if (!reconcile_calculated) // reconcile이 계산되지 않았다면 이 조건문으로 들어옴
                {
                    bool all_augmented_pub_keys = true;

                    for (int i = 0; i < stug_index; i++) // 모든 X_i를 알고 있는지 검사
                    {
                        if (!check_augmented_pub_keys[i])
                        {
                            all_augmented_pub_keys = false;
                            break;
                        }
                    }

                    if (all_augmented_pub_keys) // 모든 X_i가 계산되었다면 reconcile 계산
                    {
                        calculate_reconcile(stug_index, sec_keys[stug_index-1], reconcile, session_keys[num_peer2 - 1], hashed_keys[num_peer2-1], &ctx); // reconcile 계산
                        reconcile_calculated = true; // reconcile이 계산되었다고 알림
                    }
                }

                send(sd, &option, sizeof(option), 0); // option을 peer i에게 보내줌.

                if (option == 1) // peer N-2까지 모든 값을 다 받으면 arbiter는 그제서야 aug pub key 계산.
                {
                    calculate_augmented_pubkey(stug_index - 1, stug_index, sec_keys[stug_index-1], &ctx); // arbiter의 aug pub key 계산
                    check_augmented_pub_keys[stug_index - 1] = true; // arbiter의 aug pub key가 계산되었다고 설정
                }

                first_process = !option_check[option][peer]; // 해당 option의 연산을 여러 번 반복하지 않도록 first_process 검사
                send(sd, &first_process, sizeof(first_process), 0); // first_process 여부를 보내줌

                if (!first_process) // first process가 아니면 for문 빠져나옴, 즉 한 번 주고 받은 이상 밑의 프로세스 진행 X
                    continue;

		if (strcmp("join", mode) == 0) // mode가 join일 경우
		{
                switch (option)
                {
                    case 0: // case 0에서 peer i로부터 z_j 수신 (j는 peer i의 stug index)
                    {
			if (index[peer]==-1) // stug index가 -1일 경우, 즉 peer 2~{N-2}의 경우 아무 것도 안함
			{
				//printf("option 0 clear with peer %d!\n", peer);
				break;
			}
                        recv(sd, pub_keys[index[peer]], POLY_LEN * sizeof(uint32_t), 0); // peer i로부터 z_j 수신
			if (peer==1)
			{
				recv(sd, sec_keys[peer], POLY_LEN * sizeof(uint32_t), 0); // peer 1로부터 secrec key s_1 수신			
			}
                        //printf("option 0 clear with peer %d!\n", peer);
                        break;
                    }
                    case 1: // case 1에서 z(모든 z_i의 concatenation)를 각 peer i에게 전달 후 X_j 수신 (j는 peer i의 stug index)
                    {
                        send(sd, pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0); // z를 peer i에게 전달
			if (index[peer]==-1) // stug index가 -1일 경우, 즉 peer 2~{N-2}의 경우 break 
			{
				//printf("option 1 clear with peer %d!\n", peer);
				break;
			}
                        recv(sd, result, sizeof(result), 0); // peer i로부터 X_j 수신 
                        memcpy(augmented_pub_keys[index[peer]], result, sizeof(augmented_pub_keys[index[peer]]));
                        check_augmented_pub_keys[index[peer]] = true; // X_j 계산되었다고 설정
                        //printf("option 1 clear with peer %d!\n", peer);
                        break;
                    }
                    case 2: // case 2에서 X (모든 X_i의 concatenation)를 각 peer i에게 전달
                    {
                        send(sd, augmented_pub_keys, sizeof(uint32_t) * stug_index * POLY_LEN, 0); // X를 peer i에게 전달
                        //printf("option 2 clear with peer %d!\n", peer);
                        break;
                    }
                    case 3: // case 3에서 각 peer i에게 reconcile 전달 (모든 peer와 option 2 프로세스를 완료한 후 switch 문에 들어오기 전에 reconcile이 계산됨)
                    {
                        send(sd, reconcile, sizeof(reconcile), 0); // reconcile 전달
			if (2<=peer&&peer<num_peer-1)
			{
				send(sd, sec_keys[1], POLY_LEN * sizeof(uint32_t), 0); // peer 2~{N-1}의 경우 secret key s_1 전달
			}
			recv(sd, hashed_keys[peer], sizeof(hashed_keys[peer]), 0); // peer i로부터 session key sk_i 수신
                        //printf("option 3 clear with peer %d!\n", peer);
     		    }
		}
		}
		else // mode가 leave, static일 경우
		{
                switch (option)
                {
                    case 0: // case 0에서 peer i로부터 z_i 수신 (여기서는 peer i의 stug_index=i임)
                    { 
                        recv(sd, pub_keys[peer], POLY_LEN * sizeof(uint32_t), 0); // peer i로부터 z_i 수신
                        //printf("option 0 clear with peer %d!\n", peer);
                        break;
                    }
                    case 1: // case 1에서 z(모든 z_i의 concatenation)를 각 peer i에게 전달 후 X_i 수신
                    {
                        send(sd, pub_keys, sizeof(uint32_t) * num_peer2 * POLY_LEN, 0); // z를 peer i에게 전달
                        recv(sd, result, sizeof(result), 0); // peer i로부터 X_i 수신 
                        memcpy(augmented_pub_keys[peer], result, sizeof(augmented_pub_keys[peer]));
                        check_augmented_pub_keys[peer] = true; // X_i 계산되었다고 설정
                        //printf("option 1 clear with peer %d!\n", peer);
                        break;
                    }
                    case 2: // case 2에서 X (모든 X_i의 concatenation)를 각 peer i에게 전달
                    {
                        send(sd, augmented_pub_keys, sizeof(uint32_t) * num_peer2 * POLY_LEN, 0); // X를 peer i에게 전달
                        //printf("option 2 clear with peer %d!\n", peer);
                        break;
                    }
                    case 3: // case 3에서 각 peer i에게 reconcile 전달 (모든 peer와 option 2 프로세스를 완료한 후 switch 문에 들어오기 전에 reconcile이 계산됨)
                    {
                        send(sd, reconcile, sizeof(reconcile), 0); // reconcile 전달
			recv(sd, hashed_keys[peer], sizeof(hashed_keys[peer]), 0); // peer i로부터 session key sk_i 수신
                        //printf("option 3 clear with peer %d!\n", peer);		
                    }
                }
		}
                option_check[option][peer] = true; // 해당 peer의 option이 완료되었다고 설정
                option = next_option(option, num_peer2); // 정상적으로 모든 peer와 데이터 통신이 되었다면 option 1 증가, 아직 해당 option을 완료하지 않은 peer가 있다면 증가 X 상태로 for문 종료 
            }
        } 
    }
    printf("Arbiter (Peer %d) hashed key : ", num_peer2-1); // arbiter의 session key 출력
    for (int i = 0; i < 129; i++)
        printf("%c", hashed_keys[num_peer2 - 1][i]);
    printf("\n");
    //close(client_socket);
}

int main(int argc, char *argv[])
{
    int num_peer = 3; // default값은 static, 3명으로 설정함
    int num_peer2 = 3;
    char *mode="static";

    int server_port = 4000;
    char op;
  
    while ((op = getopt(argc, argv, "p:m:a:b:")) != -1)
    {
        switch (op)
        {
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'm': // mode
                mode        = optarg;
                break;
            case 'a': // after membership change
                num_peer2      = atoi(optarg);
                break;
            case 'b': // before membership change
                num_peer        = atoi(optarg);
                break;
        }
    }

    run_server(num_peer2, num_peer, server_port, mode);
    return 0;
}

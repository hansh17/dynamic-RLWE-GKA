<client.c>
void poly_init(int peer) -> 
int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx)로 대체
여기서 a는 rlwe_table.h에 있는 a를 뜻함

void calculate_pub_key_prime(uint32_t result[POLY_LEN], int peer, int num_peer) 
-> int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx)로 대체

int calculate_session_key(int peer, int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx) 추가
: 최종 키 계산하는 함수. 수신받은 rec[16]을 이용하여 계산

<server.c>
void poly_init(int peer) -> 
int calculate_pubkey(int peer, const uint32_t *a, uint32_t s[1024], FFT_CTX *ctx)로 대체

int calculate_augmented_pubkey(int peer, int num_peer, uint32_t s[1024],  FFT_CTX *ctx) 추가
: server도 하나의 노드이므로 중간 키 계산이 필요함.

void calculate_reconcile(void) ->
int calculate_reconcile(int num_peer, uint32_t s[1024], uint64_t rec[16], uint64_t k[16], FFT_CTX *ctx)로 대체
: rec와 key를 계산하는 함수

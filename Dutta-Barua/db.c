#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>	// for ASN1_bn_print().
#include <inttypes.h>
#include <sys/time.h>

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

// DHkeypair_print() and DHsecret_print() are test function for this example.

#define ITERATIONS 10000

#if defined(__i386__)

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

void DHkeypair_print(const char *title, const DH *dh, int indent)
{
	BIO *out;
	unsigned char *m;

	out=BIO_new_fp(stdout, BIO_NOCLOSE);
	m=OPENSSL_malloc(DH_size(dh)+10);

	BIO_indent(out, indent, 128);
	BIO_printf(out, "%s: (%d bit)\n", title, BN_num_bits(dh->p));
	indent +=4;
	ASN1_bn_print(out, "Private-key:", dh->priv_key, m, indent);
	ASN1_bn_print(out, "Public-key:", dh->pub_key, m, indent);

	OPENSSL_free(m);
	BIO_free(out);
}

void DHsecret_print(const char *title, const DH *dh, const unsigned char *secret, const int secretLen, int indent)
{
	BIO *out;
	BIGNUM *bnSecret;
	unsigned char *m;

	out=BIO_new_fp(stdout, BIO_NOCLOSE);
	bnSecret=BN_bin2bn(secret, secretLen, NULL);	// convert binary to big-number structure.
	m=OPENSSL_malloc(BN_num_bits(bnSecret)+10);

	BIO_indent(out, indent, 128);
	BIO_printf(out, "%s: (%d bit)\n", title, BN_num_bits(dh->p));
	indent +=4;
	ASN1_bn_print(out, "Secret-Key:", bnSecret, m, indent);

	BN_free(bnSecret);
	OPENSSL_free(m);
	BIO_free(out);
}

int DH_genParams(DH **dh, int bits)
{
	int dhcodes=0;

	if(*dh!=NULL)
		DH_free(*dh);

	if((*dh=DH_new())==NULL)
		return 0;

	if(DH_generate_parameters_ex(*dh, bits, DH_GENERATOR_2, NULL)!=1)
	{
		eprintf("DH_generate_parameters_ex() error.\n");
		DH_free(*dh);
		return 0;
	}

	if(DH_check(*dh, &dhcodes)!=1)
	{
		eprintf("DH_check() error.\n");
		DH_free(*dh);
		return 0;
	}

	if(dhcodes!=0)
	{
		/* NB:
		 * Problems have been found with the generated paramters
		 * Handle these here - we'll just abort for this example.
		 */
		if( (dhcodes&DH_CHECK_P_NOT_PRIME) ||	// not prime
		(dhcodes&DH_CHECK_P_NOT_SAFE_PRIME) ||	// not a safe prime
		(dhcodes&DH_UNABLE_TO_CHECK_GENERATOR) ||	// unable to check the generator value
		(dhcodes&DH_NOT_SUITABLE_GENERATOR) )	// g value is not generator
		{
			eprintf("DH_check_failed.\n");
			DH_free(*dh);
			return 0;
		}
	}

	return 1;
}

void calculate_session_key()
{
	int A_leftLen, B_leftLen,  C_leftLen;
	int A_rightLen, B_rightLen,  C_rightLen;
	unsigned char *A_left=NULL, *B_left=NULL, *C_left=NULL;
	unsigned char *A_right=NULL, *B_right=NULL, *C_right=NULL;
	unsigned char *A_final=NULL;
	//unsigned char *B_final=NULL;
	DH *dhParams=NULL, *A_dh=NULL, *B_dh=NULL, *C_dh=NULL;

	dhParams=DH_new();
	A_dh=DH_new();
	B_dh=DH_new();
	C_dh=DH_new();

	// Generate DH parameters.
	if(!DH_genParams(&dhParams, 1024))
	{
		eprintf("DH_genParams() error.\n");
		exit(1);
	}

    // Print DH parameters.
	//DHparams_print_fp(stdout, dhParams);

	// Duplicating DH parameters is shared public parameters.
	A_dh=DHparams_dup(dhParams);
	B_dh=DHparams_dup(dhParams);
	C_dh=DHparams_dup(dhParams);

    // Generate DH key pair.
	if(!DH_generate_key(A_dh) || !DH_generate_key(B_dh) || !DH_generate_key(C_dh))
	{
		eprintf("DH_generate_key() error.\n");
		exit(2);
	}

	// Print Key-pair of A and B.
	//DHkeypair_print("A's DH Key-Pair", A_dh, 4);
	//DHkeypair_print("B's DH Key-Pair", B_dh, 4);
	//DHkeypair_print("C's DH Key-Pair", C_dh, 4);


	/* ===== Exchange public-key ===== */

	// Compute the shared secret.
	A_left=OPENSSL_malloc(DH_size(A_dh));
	B_left=OPENSSL_malloc(DH_size(B_dh));
	C_left=OPENSSL_malloc(DH_size(C_dh));

	A_right=OPENSSL_malloc(DH_size(A_dh));
	B_right=OPENSSL_malloc(DH_size(B_dh));
	C_right=OPENSSL_malloc(DH_size(C_dh));

	A_final=OPENSSL_malloc(DH_size(A_dh));
	//B_final=OPENSSL_malloc(DH_size(B_dh));

// L, R calculate
	A_leftLen = DH_compute_key(A_left, C_dh->pub_key, A_dh);
	A_rightLen = DH_compute_key(A_right, B_dh->pub_key, A_dh);	

	B_leftLen = DH_compute_key(B_left, A_dh->pub_key, B_dh);
	B_rightLen = DH_compute_key(B_right, C_dh->pub_key, B_dh);	

	C_leftLen = DH_compute_key(C_left, B_dh->pub_key, C_dh);
	C_rightLen = DH_compute_key(C_right, A_dh->pub_key, C_dh);	

	BIGNUM *tmp_al = BN_new(), *tmp_bl = BN_new(), *tmp_cl = BN_new();
	BIGNUM *tmp_ar = BN_new(), *tmp_br = BN_new(), *tmp_cr = BN_new();
	
	tmp_al=BN_bin2bn(A_left, A_leftLen, NULL);
	tmp_ar=BN_bin2bn(A_right, A_rightLen, NULL);

	tmp_bl=BN_bin2bn(B_left, B_leftLen, NULL);
	tmp_br=BN_bin2bn(B_right, B_rightLen, NULL);

	tmp_cl=BN_bin2bn(C_left, C_leftLen, NULL);
	tmp_cr=BN_bin2bn(C_right, C_rightLen, NULL);	

	BIGNUM *inv_a = BN_new(), *inv_b = BN_new(), *inv_c = BN_new();

	BN_CTX* ctx;
	ctx = BN_CTX_new();

	inv_a = BN_mod_inverse(NULL, tmp_al, A_dh->p, ctx);
	inv_b = BN_mod_inverse(NULL, tmp_bl, B_dh->p, ctx);
	inv_c = BN_mod_inverse(NULL, tmp_cl, C_dh->p, ctx);

	BIGNUM *div_a = BN_new(), *div_b = BN_new(), *div_c = BN_new();
	BIGNUM *tmp = BN_new(), *tmp_a = BN_new(), *tmp_b = BN_new(), *tmp_c = BN_new();

	BN_mod_mul(div_a, inv_a, tmp_ar, A_dh->p, ctx); // Y_a
	BN_mod_mul(div_b, inv_b, tmp_br, B_dh->p, ctx); // Y_b
	BN_mod_mul(div_c, inv_c, tmp_cr, C_dh->p, ctx); // Y_c

	//BN_bn2bin(div_a, A_div);
	//BN_bn2bin(div_b, B_div);
	//BN_bn2bin(div_c, C_div);

	//BN_clear(tmp_a);

	BN_mod_mul(tmp_b,div_b, tmp_ar, A_dh->p, ctx); // K_2
	BN_mod_mul(tmp_c,div_c, tmp_b, A_dh->p, ctx); // K_3
	BN_mod_mul(tmp_a,tmp_c, tmp_b, A_dh->p, ctx); // K_2*K_3
	BN_mod_mul(tmp,tmp_a, tmp_ar, A_dh->p, ctx);	

	BN_bn2bin(tmp, A_final);

	BN_clear(tmp_a);
	BN_clear(tmp_b);
	BN_clear(tmp_c);
	BN_clear(tmp);
	
	//BN_mod_mul(tmp_c,div_c, tmp_br, B_dh->p, ctx); // K_3
	//BN_mod_mul(tmp_a,div_a, tmp_c, B_dh->p, ctx); // K_1
	//BN_mod_mul(tmp_b,tmp_c, tmp_a, B_dh->p, ctx); // K_3*K_1
	//BN_mod_mul(tmp,tmp_b, tmp_br, B_dh->p, ctx);

	//	BN_bn2bin(tmp, B_final);

	//DHsecret_print("A's DH Computed-Key", A_dh, A_final, A_rightLen, 4);
	//DHsecret_print("B's DH Computed-Key", B_dh, B_final, B_rightLen, 4);

	OPENSSL_free(A_left);
	OPENSSL_free(B_left);
	OPENSSL_free(C_left);
	OPENSSL_free(A_right);
	OPENSSL_free(B_right);
	OPENSSL_free(C_right);

	OPENSSL_free(A_final);
	//OPENSSL_free(B_final);


	DH_free(dhParams);
	DH_free(A_dh);
	DH_free(B_dh);	
	DH_free(C_dh);
}

int main() {

	uint64_t cycles_start, cycles_end;
	struct timeval timeval_start, timeval_end;

	printf("%-30s %15s %15s %15s\n", "Operation", "Iterations", "usec (avg)", "cycles (avg)");
	printf("------------------------------------------------------------------------------\n");

	TIME_OPERATION(calculate_session_key(), "calculate session key", ITERATIONS / 50)

	return 0;
}

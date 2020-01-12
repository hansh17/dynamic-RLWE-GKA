#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>	// for ASN1_bn_print().

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

// DHkeypair_print() and DHsecret_print() are test function for this example.

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

void main()
{
	int A_secretLen, B_secretLen;
	unsigned char *A_secret=NULL, *B_secret=NULL;
	DH *dhParams=NULL, *A_dh=NULL, *B_dh=NULL;

	dhParams=DH_new();
	A_dh=DH_new();
	B_dh=DH_new();

	// Generate DH parameters.
	if(!DH_genParams(&dhParams, 3072))
	{
		eprintf("DH_genParams() error.\n");
		exit(1);
	}

    // Print DH parameters.
	DHparams_print_fp(stdout, dhParams);

	// Duplicating DH parameters is shared public parameters.
	A_dh=DHparams_dup(dhParams);
	B_dh=DHparams_dup(dhParams);

    // Generate DH key pair.
	if(!DH_generate_key(A_dh) || !DH_generate_key(B_dh))
	{
		eprintf("DH_generate_key() error.\n");
		exit(2);
	}

	// Print Key-pair of A and B.
	DHkeypair_print("A's DH Key-Pair", A_dh, 4);
	DHkeypair_print("B's DH Key-Pair", B_dh, 4);

	/* ===== Exchange public-key ===== */

	// Compute the shared secret.
	A_secret=OPENSSL_malloc(DH_size(A_dh));
	B_secret=OPENSSL_malloc(DH_size(B_dh));

	if((A_secretLen=DH_compute_key(A_secret, B_dh->pub_key, A_dh))<=0)
	{
		eprintf("A - DH_generate_key() error.\n");
		exit(3);
	}
	DHsecret_print("A's DH Computed-Key", B_dh, A_secret, A_secretLen, 4);

	if((B_secretLen=DH_compute_key(B_secret, A_dh->pub_key, B_dh))<=0)
	{
		eprintf("B - DH_generate_key() error.\n");
		exit(3);
	}
	DHsecret_print("B's DH Computed-Key", B_dh, B_secret, B_secretLen, 4);

	OPENSSL_free(A_secret);
	OPENSSL_free(B_secret);
	DH_free(dhParams);
	DH_free(A_dh);
	DH_free(B_dh);
}

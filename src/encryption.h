#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <unistd.h>
#include "utils.h"

RSA *rsa_keypair_server = NULL;
RSA *rsa_keypair_client[64];//we have maximum 64 clients
unsigned char plain_text[4096];
unsigned char ciphertext[256]; // Sufficient size for a 2048-bit key

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void generate_keypair(RSA **rsa, int bits) {
    BIGNUM *bne = BN_new();
    RSA *keypair = RSA_new();

    // public exponent (65537)
    if (!BN_set_word(bne, RSA_F4)) {
        handleErrors();
    }

    // Generate keypair
    if (!RSA_generate_key_ex(keypair, bits, bne, NULL)) {
        handleErrors();
    }

    *rsa = keypair;

    BN_free(bne);
}

void rsa_encrypt(const unsigned char *plaintext, int plaintext_len, RSA *rsa, unsigned char *ciphertext) {
    int len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        handleErrors();
    }
}

void rsa_decrypt(const unsigned char *ciphertext, int ciphertext_len, RSA *rsa, unsigned char *decrypted) {
    int len = RSA_private_decrypt(ciphertext_len, ciphertext, decrypted, rsa, RSA_PKCS1_PADDING);
    if (len == -1) {
        handleErrors();
    }
}

#pragma GCC diagnostic pop
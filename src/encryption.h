#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

RSA *rsa_keypair_server = NULL;
RSA *rsa_keypair_client = NULL;
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

// void send_public_key_to_client(RSA *rsa_keypair) {
//     // Check if the RSA object is valid
//     if (rsa_keypair == NULL) {
//         // Handle error
//         return;
//     }

//     // Get the public key components (modulus and public exponent)
//     const BIGNUM *modulus = NULL;
//     const BIGNUM *exponent = NULL;
//     RSA_get0_key(rsa_keypair, &modulus, &exponent, NULL);

//     // Convert the components to hexadecimal strings for transmission
//     char *modulus_hex = BN_bn2hex(modulus);
//     char *exponent_hex = BN_bn2hex(exponent);

//     // Send modulus_hex and exponent_hex to the client using printf
//     printf("Modulus: %s\n", modulus_hex);
//     printf("Exponent: %s\n", exponent_hex);

//     // Free the memory allocated for the hexadecimal strings
//     OPENSSL_free(modulus_hex);
//     OPENSSL_free(exponent_hex);
// }
#include "monocypher.c"
#include <string.h>
#include <stdio.h>

int main() {
#define TEXT_SIZE 70
    uint8_t mac[16];
    uint8_t cipher_text[TEXT_SIZE];
    uint8_t key[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    uint8_t nonce[24] = { 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124 };
    const uint8_t ad[32] = "ojej plain extra data";
    size_t ad_size = strlen((const char*)ad);
    const uint8_t text_to_encrypt[TEXT_SIZE] = "ojej secret";
    printf("Plain text: %s\n", text_to_encrypt);

    //crypto_lock_aead(uint8_t mac[16], uint8_t *cipher_text, const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t ad_size, const uint8_t *plain_text, size_t text_size);
    crypto_lock_aead(mac, cipher_text, key, nonce, ad, ad_size, text_to_encrypt, strlen((const char*)text_to_encrypt));

    printf("Cipher text: ");
    for(int i=0; i<strlen((const char*)text_to_encrypt); i++) {
        printf(" %i ", cipher_text[i]);
    }
    printf("\n");

    uint8_t decrypted[TEXT_SIZE];
    //crypto_unlock_aead(uint8_t *plain_text, const uint8_t key[32], const uint8_t nonce[24], const uint8_t mac[16], const uint8_t *ad, size_t ad_size, const uint8_t *cipher_text, size_t text_size);
    int ret = crypto_unlock_aead(decrypted, key, nonce, mac, ad, ad_size, cipher_text, strlen((const char*)text_to_encrypt));
    char* decrypted_ch = (char*)decrypted;
    decrypted_ch[strlen((const char*)text_to_encrypt)] = '\0';
    printf("unlock ret = %i\n", ret);
    printf("decrypted = '%s'\n", decrypted_ch);
}

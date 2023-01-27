/*

The MIT License (MIT)

Copyright (c) 2023 Antonio Carlos Da Silva junior ( lord feistel )

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <string.h>

#include "aes_gcm_siv.h"


#define VERBOSE


#ifdef VERBOSE
void print_buffer(unsigned char * buff , int size)
{
    for(int i = 0 ; i < size; i++)
              printf("%x ", buff[i]);
    printf("\n");
}
#endif


int test(uint8_t * data, uint64_t data_len, uint8_t * key, uint8_t * nonce)
{

    AES_GCM_SIV_PARAM params;

    memcpy(params.nonce, nonce,AES_NONCE_SIZE);
    memcpy(params.key, key,AES_128_KEYSIZE);
    params.data_len = data_len;

    params.data = (uint8_t*)malloc(params.data_len * sizeof(uint8_t));

    memcpy(params.data, data, params.data_len);
    params.aad_len = 0;
    params.aad = NULL;

#ifdef VERBOSE
    printf("INPUT\n");
    printf("nonce:\t\t");
    print_buffer(params.nonce, AES_NONCE_SIZE);


    printf("key:\t\t");
    print_buffer(params.key, AES_NONCE_SIZE);

    printf("data:\t\t");
    print_buffer(params.data, params.data_len);
#endif  

    //encrypt  
    aes_gcm_siv(&params, ENCRYPT);

#ifdef VERBOSE
    printf("\nOUTPUT\n");
    printf("encrypted data:\t");
    print_buffer(params.data, params.data_len);

    printf("tag:\t\t");
    print_buffer(params.tag,AES_GCM_TAG_SIZE);
#endif    

    //decrypt
    aes_gcm_siv(&params, DECRYPT);

#ifdef VERBOSE
    printf("decrypted data:\t");
    print_buffer(params.data, params.data_len);
    printf("tag\t\t");
    print_buffer(params.tag, AES_GCM_TAG_SIZE);
    printf("\n");
#endif   
    free(params.data);
 
    return 0;


}



int main (void)
{
    

    uint8_t key[AES_128_KEYSIZE]   =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t data[32]               =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t nonce[AES_NONCE_SIZE]  =   {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    test(data, sizeof(data), key,nonce);
 

    return 0;
}
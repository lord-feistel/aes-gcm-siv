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

//used on tests
#include <assert.h>

#include "aes_gcm_siv.h"


#define VERBOSE

#ifdef VERBOSE
void print_buffer(uint8_t * buff , int size)
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



    assert (memcmp(data,params.data,data_len) == 0); 
    free(params.data);
 
    return 0;


}

// The following tests were taken from :
// https://www.rfc-editor.org/rfc/rfc8452

void TEST_01 ()
{

/*
   
   Plaintext (16 bytes) =      01000000000000000000000000000000
   AAD (0 bytes) =
   Key =                       01000000000000000000000000000000
   Nonce =                     030000000000000000000000
   Record authentication key = d9b360279694941ac5dbc6987ada7377
   Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
   POLYVAL input =             01000000000000000000000000000000
                               00000000000000008000000000000000
   POLYVAL result =            20806c26e3c1de019e111255708031d6
   POLYVAL result XOR nonce =  23806c26e3c1de019e111255708031d6
   ... and masked =            23806c26e3c1de019e11125570803156
   Tag =                       303aaf90f6fe21199c6068577437a0c4
   Initial counter =           303aaf90f6fe21199c6068577437a0c4
   Result (32 bytes) =         743f7c8077ab25f8624e2e948579cf77
                               303aaf90f6fe21199c6068577437a0c4


*/


    uint8_t key[AES_128_KEYSIZE]   =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t data[16]               =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t nonce[AES_NONCE_SIZE]  =   {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    test(data, sizeof(data), key,nonce);
}


void TEST_02 ()
{

    /*
    
       Plaintext (32 bytes) =      01000000000000000000000000000000
                                   02000000000000000000000000000000
       AAD (0 bytes) =
       Key =                       01000000000000000000000000000000
       Nonce =                     030000000000000000000000
       Record authentication key = d9b360279694941ac5dbc6987ada7377
       Record encryption key =     4004a0dcd862f2a57360219d2d44ef6c
       POLYVAL input =             01000000000000000000000000000000
                                   02000000000000000000000000000000
                                   00000000000000000001000000000000
       POLYVAL result =            ce6edc9a50b36d9a98986bbf6a261c3b
       POLYVAL result XOR nonce =  cd6edc9a50b36d9a98986bbf6a261c3b
       ... and masked =            cd6edc9a50b36d9a98986bbf6a261c3b
       Tag =                       1a8e45dcd4578c667cd86847bf6155ff
       Initial counter =           1a8e45dcd4578c667cd86847bf6155ff
       Result (48 bytes) =         84e07e62ba83a6585417245d7ec413a9
                                   fe427d6315c09b57ce45f2e3936a9445
                                   1a8e45dcd4578c667cd86847bf6155ff
    */



    uint8_t key[AES_128_KEYSIZE]   =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t data[32]               =   {01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00};
    uint8_t nonce[AES_NONCE_SIZE]  =   {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    test(data, sizeof(data), key,nonce);
}


int main (void)
{
    

    TEST_01();
    TEST_02();

    return 0;
}
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
#include "test.h"

//used on tests
#include <assert.h>

#include "aes_gcm_siv.h"


void print_buffer(uint8_t * buff , int size)
{
    for(int i = 0 ; i < size; i++)
              printf("%x ", buff[i]);
    printf("\n");
}



int test(uint8_t * data, uint64_t data_len, uint8_t * key, uint8_t * nonce, uint8_t * aad, size_t aad_len)
{

    AES_GCM_SIV_PARAM params;

    memcpy(params.nonce, nonce,AES_NONCE_SIZE);
    memcpy(params.key, key,AES_128_KEYSIZE);
    params.data_len = data_len;



    params.data = (uint8_t*)malloc(params.data_len * sizeof(uint8_t));

    memcpy(params.data, data, params.data_len);


    params.aad_len = aad_len;

    if(params.aad_len == 0)
    {
        params.aad = NULL;
    }
    else
    {
        params.aad = (uint8_t*)malloc(params.aad_len * sizeof(uint8_t));
        memcpy(params.aad, aad, params.aad_len);
    }



    printf("INPUT\n");
    printf("nonce:\t\t");
    print_buffer(params.nonce, AES_NONCE_SIZE);


    printf("key:\t\t");
    print_buffer(params.key, AES_128_KEYSIZE);

    printf("data:\t\t");
    print_buffer(params.data, params.data_len);
 

    printf("\nOUTPUT\n");



    //encrypt  
    printf("\nENCRYPTION...\n\n");
    aes_gcm_siv(&params, ENCRYPT);
    printf("encrypted data:\n");
    print_buffer(params.data, params.data_len);

    printf("tag:\n");
    print_buffer(params.tag,AES_GCM_TAG_SIZE);
   

    printf("\nDECRYPTION...\n\n");

    //decrypt
    aes_gcm_siv(&params, DECRYPT);
    printf("decrypted data:\n");
    print_buffer(params.data, params.data_len);
    printf("tag\n");
    print_buffer(params.tag, AES_GCM_TAG_SIZE);
    printf("\n");
  



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
    test(data, sizeof(data), key,nonce, NULL, 0);
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
    test(data, sizeof(data), key,nonce, NULL, 0);

}


void TEST_03 ()
{

    //AAD

    /*
    
        Plaintext (15 bytes) =      0d8c8451178082355c9e940fea2f58
        AAD (25 bytes) =            2950a70d5a1db2316fd568378da107b5
                                    2b0da55210cc1c1b0a
        Key =                       2d4ed87da44102952ef94b02b805249b
        Nonce =                     ac80e6f61455bfac8308a2d4
        Record authentication key = 0b00a29a83e7e95b92e3a0783b29f140
        Record encryption key =     a430c27f285aed913005975c42eed5f3
        POLYVAL input =             2950a70d5a1db2316fd568378da107b5
                                    2b0da55210cc1c1b0a00000000000000
                                    0d8c8451178082355c9e940fea2f5800
                                    c8000000000000007800000000000000
        POLYVAL result =            1086ef25247aa41009bbc40871d9b350
        POLYVAL result XOR nonce =  bc0609d3302f1bbc8ab366dc71d9b350
   ... and masked =                 bc0609d3302f1bbc8ab366dc71d9b350
   Tag =                            83b3449b9f39552de99dc214a1190b0b
   Initial counter =                83b3449b9f39552de99dc214a1190b8b
   Result (31 bytes) =              c9ff545e07b88a015f05b274540aa183
                                    b3449b9f39552de99dc214a1190b0b
    
    
    */

	uint8_t nonce[12]   		   	    =   { 0xac, 0x80, 0xe6, 0xf6, 0x14, 0x55, 0xbf, 0xac, 0x83, 0x08, 0xa2, 0xd4 };
	uint8_t data[15]    		   		=   { 0x0d, 0x8c, 0x84, 0x51, 0x17, 0x80, 0x82, 0x35, 0x5c, 0x9e, 0x94, 0x0f, 0xea, 0x2f, 0x58};
	uint8_t aad_test[25]				=	{ 0x29, 0x50, 0xa7, 0x0d, 0x5a, 0x1d, 0xb2, 0x31, 0x6f, 0xd5, 0x68, 0x37, 0x8d, 0xa1, 0x07, 0xb5, 0x2b, 0x0d, 0xa5, 0x52, 0x10, 0xcc, 0x1c, 0x1b, 0x0a};

    uint8_t key[16]   	                =   { 0x2d, 0x4e, 0xd8, 0x7d, 0xa4, 0x41, 0x02, 0x95, 0x2e, 0xf9, 0x4b, 0x02, 0xb8, 0x05, 0x24, 0x9b};

	


    
    test(data, sizeof(data), key,nonce, aad_test, 25);






}





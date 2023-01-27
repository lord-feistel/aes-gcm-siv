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

#ifndef _AES_GCM_SIV_
#define _AES_GCM_SIV_



#define AES_GCM_TAG_SIZE      16
#define AES_BLOCK_SIZE        16
#define AES_128_KEYSIZE       16
#define AES_NONCE_SIZE        12

#define SHIFT_8_BITS          8
#define SHIFT_16_BITS         16
#define SHIFT_24_BITS         24

#define DWORD_128_BITS        2
#define DWORD_LOW             0
#define DWORD_HIGH            1  

#define MULTIPLICATON_SHIFTS  64

#define ERROR   -1
#define SUCCESS  0

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <string.h>

typedef enum CRYPT_OP { ENCRYPT, DECRYPT } OPERATION;

typedef struct CRYPT_PARAM
{

  uint8_t   nonce [AES_NONCE_SIZE]; 
  uint8_t   key   [AES_128_KEYSIZE]; 
  uint8_t   tag   [AES_GCM_TAG_SIZE];
  uint8_t * data; 
  uint8_t * aad;
  uint64_t  data_len;
  uint64_t  aad_len;
} AES_GCM_SIV_PARAM ;


void aes_gcm_siv( AES_GCM_SIV_PARAM * params ,  OPERATION operation);

#endif
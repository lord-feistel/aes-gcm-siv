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

#include"aes_gcm_siv.h"

#ifdef DEBUG

void print_stuff(unsigned char * buff , int size)
{
    for(int i = 0 ; i < size; i++)
              printf("%x ", buff[i]);
    printf("\n");
}

#endif

void convert_to_counter(uint8_t offset, uint8_t *buffer) 
{
    buffer[0] = (uint8_t)  offset;
    buffer[1] = (uint8_t)( offset >> SHIFT_8_BITS);
    buffer[2] = (uint8_t)( offset >> SHIFT_16_BITS);
    buffer[3] = (uint8_t)( offset >> SHIFT_24_BITS);
}


uint8_t get_bit_value(uint64_t buffer, uint8_t pos)
{
	return ((buffer & (((uint64_t)1)<<pos)) != 0) ? 1 : 0 ;
}

void multiplication(uint64_t multiplier_low, 
                    uint64_t multiplier_high, 
                    uint64_t* destination)

{
	
	destination[DWORD_LOW]  = 0;
	destination[DWORD_HIGH] = 0;
	
	for(uint8_t index=0; index < MULTIPLICATON_SHIFTS; index++)
	{
		if(get_bit_value(multiplier_high,index) == 1)
    {
      destination[DWORD_HIGH]^=multiplier_low;
    } 
		destination[DWORD_LOW]>>=1;
    if(get_bit_value(destination[DWORD_HIGH],0) == 1)
    {
      destination[DWORD_LOW]^=(((uint64_t)1) << (MULTIPLICATON_SHIFTS -1));
    } 
      
		destination[DWORD_HIGH]>>=1;
	}
}

int  mul(uint64_t* src1, uint64_t* src2, uint64_t* destination, uint8_t in)
{
	
  if      (in == 0)
        multiplication(src1[DWORD_LOW],src2[DWORD_LOW],destination);
  else if (in == 1)
        multiplication(src1[DWORD_HIGH],src2[DWORD_LOW],destination);
  else if (in == 2)
        multiplication(src1[DWORD_LOW],src2[DWORD_HIGH],destination);
  else if (in == 3)
        multiplication(src1[DWORD_HIGH],src2[DWORD_HIGH],destination);
  else
        return ERROR;

  return SUCCESS;
  
}


void galois_field_128_bits_mul(uint64_t* mul_operator_1, uint64_t* mul_operator_2, uint64_t* result)
{  

  uint64_t op1[DWORD_128_BITS]; 
  uint64_t op2[DWORD_128_BITS]; 
  uint64_t op3[DWORD_128_BITS]; 
  uint64_t op4[DWORD_128_BITS];
	
  uint64_t MASK[DWORD_128_BITS] = { 0x1, 0xc200000000000000 };

  // Avoiding error check because speed
  // But in debugging is possible to check
  // which multiplication step had errors

  // All of it is pretty standard
  // it can be found in mbedtls or any 
  // other open source cryptography library
  
  // constant mutiplication
  mul(mul_operator_1,mul_operator_2,op1,0);
  mul(mul_operator_1,mul_operator_2,op3,1);
  mul(mul_operator_1,mul_operator_2,op2,2);
  mul(mul_operator_1,mul_operator_2,op4,3);
	
	op2[0] ^= op3[0];
	op2[1] ^= op3[1];
	op3[0] = 0;
	op3[1] = op2[0];
	op2[0] = op2[1];
	op2[1] = 0;
	op1[0] ^= op3[0];
	op1[1] ^= op3[1];
	op4[0] ^= op2[0];
	op4[1] ^= op2[1];
	
  mul(MASK, op1,op2,0x01);

	((uint32_t*) op3)[0] = ((uint32_t*) op1)[2];
	((uint32_t*) op3)[1] = ((uint32_t*) op1)[3];
	((uint32_t*) op3)[2] = ((uint32_t*) op1)[0];
	((uint32_t*) op3)[3] = ((uint32_t*) op1)[1];
	
	op1[0] = op2[0] ^ op3[0];
	op1[1] = op2[1] ^ op3[1];

  mul(MASK,op1,op2,0x01);
  ((uint32_t*)op3)[0] = ((uint32_t*)op1)[2];
	((uint32_t*)op3)[1] = ((uint32_t*)op1)[3];
	((uint32_t*)op3)[2] = ((uint32_t*)op1)[0];
	((uint32_t*)op3)[3] = ((uint32_t*)op1)[1];
	
	op1[0] = op2[0] ^ op3[0];
	op1[1] = op2[1] ^ op3[1];
	
	result[0] = op4[0] ^ op1[0];
	result[1] = op4[1] ^ op1[1];
}

void POLYVAL(uint64_t* input, uint64_t* H, uint64_t len, uint64_t* result)
{	
    
  // FOR GCC
  // TODO adapt to CLANG
  #define ALIGN16  __attribute__  ( (aligned (16)))

	uint64_t tmp_res[DWORD_128_BITS];
	uint64_t in[DWORD_128_BITS];

	tmp_res[DWORD_LOW] = result[DWORD_LOW];
  tmp_res[DWORD_HIGH] = result[DWORD_HIGH];

	int i;
	int blocks = len/16;
	if (blocks == 0) return;
	
	for (i = 0; i < blocks; i++) {

		in[DWORD_LOW]  = input[ 2 * i + DWORD_LOW];
    in[DWORD_HIGH] = input[ 2 * i + DWORD_HIGH];
		
		tmp_res[DWORD_LOW]  ^= in[DWORD_LOW];
		tmp_res[DWORD_HIGH] ^= in[DWORD_HIGH];

    // Where magic happens
		galois_field_128_bits_mul(tmp_res, H, tmp_res);
	}
	result[DWORD_LOW] = tmp_res[DWORD_LOW];
	result[DWORD_HIGH] = tmp_res[DWORD_HIGH];
}
 

unsigned char *  gen_key(EVP_CIPHER_CTX *ctx, int ctrStart, int ctrEnd, unsigned char * nonce) {

   
  unsigned char * key = (unsigned char *)malloc((ctrEnd - ctrStart + 1) * 8);
  unsigned char block [AES_BLOCK_SIZE];



  int len = AES_BLOCK_SIZE;

 for (int i = ctrStart; i <= ctrEnd; i++) 
  {
       convert_to_counter(i, nonce);
       EVP_EncryptUpdate(ctx, block, &len, nonce, len);
       int block_start = (i - ctrStart) * 8;
       memcpy(&key[block_start], block, 8);

  }

    return key;
  }


EVP_CIPHER_CTX * init_crypto(unsigned char * key, const EVP_CIPHER * MODE, unsigned char * iv)
{

    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf ("EVP_CIPHER_CTX_new() failed\n");
        exit (EXIT_FAILURE);
    }

    if (1 != EVP_EncryptInit_ex(ctx, MODE, NULL, key, iv)) {
        printf ("EVP_EncryptInit_ex failed\n");
        exit (EXIT_FAILURE);
    }

    return ctx;
}

  unsigned char *  hash( unsigned char  * enc_key, 
                         unsigned char  * auth_key,
                         unsigned char  * nonce, 
                         unsigned char  * plaintext, 
                         unsigned char  * AAD,
                         uint64_t         MSG_len,
                         uint64_t          AAD_len ) 
  {


	uint64_t msg_pad = 0;
	uint64_t aad_pad = 0;
  uint64_t POLYV[DWORD_128_BITS] = {0};
  unsigned char pol [AES_BLOCK_SIZE]= {0};
  
  int len = 16 ;
  uint8_t *  tag = (unsigned char *) malloc(AES_GCM_TAG_SIZE);


  if ((AAD_len % AES_BLOCK_SIZE) != 0) {
		aad_pad = AES_BLOCK_SIZE - (AAD_len % AES_BLOCK_SIZE);
	}
	if ((MSG_len % AES_BLOCK_SIZE) != 0) {
		msg_pad = AES_BLOCK_SIZE - (MSG_len % AES_BLOCK_SIZE);
	}


	uint64_t LENBLK[2] = {(AAD_len<<3), (MSG_len<<3)};


 	POLYVAL((uint64_t*)AAD, (uint64_t*)auth_key, AAD_len + aad_pad, POLYV);
	POLYVAL((uint64_t*)plaintext, (uint64_t*)auth_key, MSG_len + msg_pad, POLYV);
  POLYVAL(LENBLK, (uint64_t*)auth_key, AES_BLOCK_SIZE, POLYV);

#ifdef DEBUG
  printf("Polynomials:\n");
  printf("POLYVAL[0]: %016llx POLYVAL[1]: %016llx \n",POLYV[0], POLYV[1]);
	printf("LENBLK[0]: %016llx LENBLK[1]: %016llx \n",LENBLK[0], LENBLK[1]);
#endif
 
  EVP_CIPHER_CTX * tag_encryption_ctx = init_crypto(enc_key, EVP_aes_128_ecb(),NULL);  
  
  memcpy(pol,(uint8_t *)POLYV, AES_BLOCK_SIZE);                                  

#ifdef  DEBUG   
  printf("Before xor with nonce:\n");
  print_stuff(pol,16);   
  printf("Nonce:\n");
  print_stuff(nonce,12);   
#endif

  for (int i = 0; i < AES_NONCE_SIZE; i++) 
  {
      pol[i] ^= nonce[i];
  }
    
  ((uint8_t*)pol)[AES_BLOCK_SIZE - 1] &= ~0x80;

#ifdef  DEBUG  
  printf("After xor with nonce:\n");
  print_stuff(pol,16);   
#endif

  EVP_EncryptUpdate(tag_encryption_ctx, tag, &len, pol, len);

#ifdef DEBUG  
  printf("tag:\n");
  print_stuff(tag,16);
#endif

  return tag;

  }

void aes_gcm_siv( AES_GCM_SIV_PARAM * params ,  OPERATION operation)
{
   
    EVP_CIPHER_CTX * ecb_ctx;
    EVP_CIPHER_CTX * ctr_ctx;
    unsigned char * tag = NULL; 

    unsigned char adjusted_nonce[AES_BLOCK_SIZE] = {0};

    memset(adjusted_nonce , 0, AES_BLOCK_SIZE);
    memcpy(adjusted_nonce + 4, params->nonce, AES_NONCE_SIZE);

    ecb_ctx = init_crypto(params->key, EVP_aes_128_ecb(),NULL);

    // generates key for the hash
    unsigned char * hash_key = gen_key(ecb_ctx, 0, 1, adjusted_nonce);

#ifdef  DEBUG    
    printf("hash key:\n");
    print_stuff(hash_key,AES_BLOCK_SIZE); 
#endif

    // generates the key for the encryption
    unsigned char * encryption_key = gen_key(ecb_ctx, 2, 3, adjusted_nonce);
#ifdef  DEBUG       
    printf("cryptography key:\n");
    print_stuff(encryption_key, AES_BLOCK_SIZE);
#endif

    EVP_CIPHER_CTX_free(ecb_ctx);

    



    int len = params->data_len;
    uint8_t * msg = (uint8_t*) malloc(params->data_len * sizeof(u_int8_t));

    if(operation == ENCRYPT)
    {

      // In the encryption the hash is before the usage of AES-CTR
      // beacuse the tag is needed to be used as IV 
      // but in the decryption it occurs after in order to check the 
      // operation integrity

      tag = hash ( encryption_key, 
                   hash_key, 
                   params->nonce, 
                   params->data, 
                   params->aad, 
                   params->data_len, 
                   params->aad_len);


        ctr_ctx = init_crypto(encryption_key, EVP_aes_128_ctr(), tag);
        EVP_EncryptUpdate(ctr_ctx, msg, &len,  params->data, len);
        EVP_EncryptFinal_ex(ctr_ctx, msg + len, &len);
    }else{

        EVP_CIPHER_CTX * ctx_dec = EVP_CIPHER_CTX_new();
        EVP_DecryptInit(ctx_dec, EVP_aes_128_ctr(),  encryption_key, params->tag);
        EVP_DecryptUpdate(ctx_dec, msg, &len, params->data, params->data_len);
        EVP_DecryptFinal_ex(ctx_dec, msg + len, &len);

        tag = hash( encryption_key, 
                    hash_key, 
                    params->nonce, 
                    msg, 
                    params->aad, 
                    params->data_len, 
                    params->aad_len);
    }

#ifdef  DEBUG  
    printf("encrypted text:\n");
    print_stuff(msg,AES_BLOCK_SIZE);
#endif

    //clean up
    
    memset(hash_key,0,AES_128_KEYSIZE);
    memset(encryption_key,0,AES_128_KEYSIZE);

    free(hash_key);
    free(encryption_key);


    memcpy(params->data, msg, params->data_len);
    memcpy(params->tag, tag, AES_GCM_TAG_SIZE);

    memset(tag,0,AES_GCM_TAG_SIZE);
    free(tag);


    memset(msg, 0,params->data_len);
    free(msg);
   
}


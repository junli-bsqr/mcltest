/**
 * Copyright (c) 2016 Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdio.h>
#include <component_auth.h>
#include "mcl_ecdh_runtime.h"
#include "mcl_rsa_runtime.h"

static void testc25519()
{
  int res,i;
  char *pp="M0ng00se";
  char s0[MCL_EGS2],s1[MCL_EGS2],w0[2*MCL_EFS2+1],w1[2*MCL_EFS2+1],z0[MCL_EFS2];
  char z1[MCL_EFS2],seed[32],key[MCL_EAS],salt[32],pw[20],p1[30],p2[30];
  char v[2*MCL_EFS2+1],m[32],c[64],t[32],cs[MCL_EGS2],ds[MCL_EGS2];
  mcl_octet S0={0,sizeof(s0),s0};
  mcl_octet S1={0,sizeof(s1),s1};
  mcl_octet W0={0,sizeof(w0),w0};
  mcl_octet W1={0,sizeof(w1),w1};
  mcl_octet Z0={0,sizeof(z0),z0};
  mcl_octet Z1={0,sizeof(z1),z1};
  mcl_octet SEED={0,sizeof(seed),seed};
  mcl_octet KEY={0,sizeof(key),key};
  mcl_octet SALT={0,sizeof(salt),salt};
  mcl_octet PW={0,sizeof(pw),pw};
  mcl_octet P1={0,sizeof(p1),p1};
  mcl_octet P2={0,sizeof(p2),p2};
  mcl_octet V={0,sizeof(v),v};
  mcl_octet M={0,sizeof(m),m};
  mcl_octet C={0,sizeof(c),c};
  mcl_octet T={0,sizeof(t),t};
  mcl_octet CS={0,sizeof(cs),cs};
  mcl_octet DS={0,sizeof(ds),ds};
  csprng RNG;                

  /* fake random seed source */
  char* seedHex = "d50f4137faff934edfa309c110522f6f5c0ccb0d64e5bf4bf8ef79d1fe21031a";
  //MCL_hex2bin(seedHex, SEED.val, 64);
  SEED.len=32;				
  SEED.val = seedHex;

  /* initialise strong RNG */
  MCL_CREATE_CSPRNG_C25519(&RNG,&SEED);   

  /* fake random salt value */
  char* saltHex = "7981eaa63589e7e4";
  MCL_hex2bin(saltHex, SALT.val, strlen(seedHex));
  SALT.len=8;				

  printf("C25519 Alice's Passphrase= %s\r\n",pp);
  MCL_OCT_empty(&PW);
  // set Password from string
  MCL_OCT_jstring(&PW,pp);   

  /* private key S0 of size MCL_EGS1 bytes derived from Password and Salt */
  MCL_PBKDF2_C25519(MCL_HASH_TYPE_ECC,&PW,&SALT,1000,MCL_EGS2,&S0);
  char ttt1[] = {
    0x08,0xc6,0xa4,0x2d,0x0a,0x67,0xb5,0xbe,0x07,0xfb,0x64,0x60,0x97,0xb4,0x8a,0xf7,
    0x7d,0x32,0x2b,0x00,0x38,0x5d,0xe6,0xfb,0x0d,0x46,0xc7,0x90,0xbd,0xa8,0x4c,0x84
  };
  S0.len = sizeof(ttt1);
  S0.val = ttt1;
  printf("C25519 Alices private key= 0x");
  MCL_OCT_output(&S0);
  printf("\r\n");

  /* Generate Key pair S/W */
  MCL_ECP_KEY_PAIR_GENERATE_C25519(NULL,&S0,&W0);
  res=MCL_ECP_PUBLIC_KEY_VALIDATE_C25519(1,&W0);
  if (res!=0) {
    printf("MCL_ECP Public Key is invalid!\r\n");
  }

  printf("C25519 Alice's public key= 0x");  
  MCL_OCT_output(&W0);
  printf("\r\n");

  /* Random private key for other party */
  MCL_ECP_KEY_PAIR_GENERATE_C25519(&RNG,&S1,&W1);

  res=MCL_ECP_PUBLIC_KEY_VALIDATE_C25519(1,&W1);
  if (res!=0) {
    printf("MCL_ECP Public Key is invalid!\r\n");
  }
  printf("C25519 Servers private key= 0x");  
  MCL_OCT_output(&S1);
  printf("\r\n");
  
  printf("C25519 Servers public key= 0x");   
  MCL_OCT_output(&W1);
  printf("\r\n");

  /* Calculate common key using DH - IEEE 1363 method */
  MCL_ECPSVDP_DH_C25519(&S0,&W1,&Z0);
  MCL_ECPSVDP_DH_C25519(&S1,&W0,&Z1);
   
  if (!MCL_OCT_comp(&Z0,&Z1)) {
    printf("*** MCL_ECPSVDP-DH Failed\r\n");
  }

  MCL_KDF2_C25519(MCL_HASH_TYPE_ECC,&Z0,NULL,MCL_EAS,&KEY);

  printf("C25519 Alice's DH Key=  0x"); 
  MCL_OCT_output(&KEY);
  printf("\r\n");

  printf("C25519 Servers DH Key=  0x"); 
  MCL_OCT_output(&KEY);
  printf("\r\n");

#if MCL_CURVETYPE!=MCL_MONTGOMERY

  printf("C25519 Testing ECIES\r\n");

  P1.len=3; P1.val[0]=0x0; P1.val[1]=0x1; P1.val[2]=0x2; 
  P2.len=4; P2.val[0]=0x0; P2.val[1]=0x1; P2.val[2]=0x2; P2.val[3]=0x3; 

  M.len=17;
  for (i=0;i<=16;i++) M.val[i]=i; 

  MCL_ECP_ECIES_ENCRYPT_C25519(MCL_HASH_TYPE_ECC,&P1,&P2,&RNG,&W1,&M,12,&V,&C,&T);

  printf("C25519 Ciphertext: \r\n"); 
  printf("V= 0x"); MCL_OCT_output(&V);
  printf("C= 0x"); MCL_OCT_output(&C);
  printf("T= 0x"); MCL_OCT_output(&T);

  if (!MCL_ECP_ECIES_DECRYPT_C25519(MCL_HASH_TYPE_ECC,&P1,&P2,&V,&C,&T,&S1,&M)) {
    printf("C25519 ECIES Decryption Failed\r\n");
  } else {
    printf("C25519 Decryption succeeded\r\n");
  }

  printf("C25519 Message is 0x"); 
  MCL_OCT_output(&M);
  printf("\r\n");

  printf("C25519 Testing ECDSA\r\n");
    char xstr[] = "Hello MCL ENCRYPT, this is a test";
    M.len = 20;//sizeof(xstr);
    M.val = xstr;

  if (MCL_ECPSP_DSA_C25519(MCL_HASH_TYPE_ECC,&RNG,&S0,&M,&CS,&DS)!=0) {
    printf("C25519 ECDSA Signature Failed\r\n");
  }

  char tcs[]={
    0x09,0x2c,0x2e,0xcc,0xb5,0xba,0xa1,0x9a,0xd3,0x2a,0xda,0x6a,0x5f,0x5e,0x87,0xd1,
    0x9f,0x81,0xff,0xf1,0x70,0xb3,0xd9,0x37,0xd2,0xdb,0x19,0xb0,0x44,0xae,0x65,0x52
    
  };
  char tds[]={
   0x0b,0x86,0xab,0x86,0x83,0x72,0x19,0xb6,0xf1,0x86,0xaa,0x34,0xb5,0x16,0xf5,0xe7,
    0x9d,0x86,0xe1,0xaa,0xbd,0x44,0xeb,0x29,0xf8,0xd5,0xcc,0x5a,0xd0,0x41,0x45,0x48
   
  };
  CS.val = tcs;
  DS.val = tds;
  printf("C25519 Signature C = 0x"); 
  MCL_OCT_output(&CS);
  printf("\r\n");
  printf("C25519 Signature D = 0x"); 
  MCL_OCT_output(&DS);
  printf("\r\n");

  if (MCL_ECPVP_DSA_C25519(MCL_HASH_TYPE_ECC,&W0,&M,&CS,&DS)!=0) {
    printf("C25519 ECDSA Verification Failed\r\n");
  } else {
    printf("C25519 ECDSA Signature/Verification succeeded \r\n");
  }
#endif

  MCL_KILL_CSPRNG_C25519(&RNG);
}
static void testc448()
{
  int res,i;
  char *pp="M0ng00se";
  char s0[MCL_EGS1],s1[MCL_EGS1],w0[2*MCL_EFS1+1],w1[2*MCL_EFS1+1],z0[MCL_EFS1];
  char z1[MCL_EFS1],seed[32],key[MCL_EAS],salt[32],pw[20],p1[30],p2[30];
  char v[2*MCL_EFS1+1],m[32],c[64],t[32],cs[MCL_EGS1],ds[MCL_EGS1];
  mcl_octet S0={0,sizeof(s0),s0};
  mcl_octet S1={0,sizeof(s1),s1};
  mcl_octet W0={0,sizeof(w0),w0};
  mcl_octet W1={0,sizeof(w1),w1};
  mcl_octet Z0={0,sizeof(z0),z0};
  mcl_octet Z1={0,sizeof(z1),z1};
  mcl_octet SEED={0,sizeof(seed),seed};
  mcl_octet KEY={0,sizeof(key),key};
  mcl_octet SALT={0,sizeof(salt),salt};
  mcl_octet PW={0,sizeof(pw),pw};
  mcl_octet P1={0,sizeof(p1),p1};
  mcl_octet P2={0,sizeof(p2),p2};
  mcl_octet V={0,sizeof(v),v};
  mcl_octet M={0,sizeof(m),m};
  mcl_octet C={0,sizeof(c),c};
  mcl_octet T={0,sizeof(t),t};
  mcl_octet CS={0,sizeof(cs),cs};
  mcl_octet DS={0,sizeof(ds),ds};
  csprng RNG;                

  /* fake random seed source */
  char* seedHex = "a50f4137faff934edfa309c110522f6f5c0ccb0d64e5bf4bf8ef79d1fe21031a";
  //MCL_hex2bin(seedHex, SEED.val, 64);
  SEED.len=32;				
  SEED.val = seedHex;

  /* initialise strong RNG */
  MCL_CREATE_CSPRNG_C448(&RNG,&SEED);   

  char ttt[] = {
    0x8b,0x13,0xd1,0xfe,0xed,0x68,0xaa,0x74,0x6d,0x33,0x9c,0xfb,0xf6,0x9a,0xc0,0x66,
    0x3a,0x45,0xc7,0x32,0x79,0x50,0xba,0x4a,0x9f,0xfe,0xa4,0xc2,0x34,0x3c,0x75,0xbf,
    0xc6,0x84,0x29,0x12,0xea,0xc2,0x35,0xd9,0x66,0x50,0xe1,0x10,0x8e,0x85,0xa6,0xac,
    0xd4,0xb3,0x61,0x48,0xbc,0x89,0xc1,0x9e
  };
  S0.len = sizeof(ttt);
  S0.val = ttt;
  printf("C448 Alices private key (%d)= 0x", MCL_EGS1);
  MCL_OCT_output(&S0);
  printf("\r\n");

  /* Generate Key pair S/W */
  MCL_ECP_KEY_PAIR_GENERATE_C448(NULL,&S0,&W0);
  res=MCL_ECP_PUBLIC_KEY_VALIDATE_C448(1,&W0);
  if (res!=0) {
    printf("MCL__ECP Public Key is invalid!\r\n");
  }

  printf("C448 Alice's public key= 0x");  
  MCL_OCT_output(&W0);
  printf("\r\n");

  char ttt1[] = {
      0x06,0x45,0xbb,0xe7,0x48,0x39,0xf6,0x93,0x75,0x6d,0x3c,0x10,0xee,0x70,0xa8,0xa6,0xa4,0xa8,0x19,0x40,0xb2,0x48,0x4e,0xe2,0xb0,0x46,0xc3,0x4d,0xf0,0x65,0xb0,0xe8,0x1e,0x9e,0xeb,0x9b,0x2d,0xe4,0x1d,0x81,0xea,0x4f,0x66,0x78,0x10,0xf1,0xa0,0x07,0x33,0x23,0xd1,0xf2,0x76,0xcc,0xf3,0xd8
  };
  S1.len = sizeof(ttt1);
  S1.val = ttt1;
  /* Random private key for other party */
  MCL_ECP_KEY_PAIR_GENERATE_C448(NULL,&S1,&W1);

  res=MCL_ECP_PUBLIC_KEY_VALIDATE_C448(1,&W1);
  if (res!=0) {
    printf("MCL_ECP Public Key is invalid!\r\n");
  }
  printf("C448 Servers private key= 0x");  
  MCL_OCT_output(&S1);
  printf("\r\n");
  
  printf("C448 Servers public key= 0x");   
  MCL_OCT_output(&W1);
  printf("\r\n");

  /* Calculate common key using DH - IEEE 1363 method */
  int ret1 = MCL_ECPSVDP_DH_C448(&S0,&W1,&Z0);
  int ret2 = MCL_ECPSVDP_DH_C448(&S1,&W0,&Z1);
   
  if (!MCL_OCT_comp(&Z0,&Z1)) {
    printf("*** MCL_ECPSVDP-DH Failed\r\n");
  }

  MCL_KDF2_C448(MCL_HASH_TYPE_ECC,&Z0,NULL,MCL_EAS,&KEY);

  printf("C448 Alice's DH Key=  0x"); 
  MCL_OCT_output(&KEY);
  printf("\r\n");

  printf("C448 Servers DH Key=  0x"); 
  MCL_OCT_output(&KEY);
  printf("\r\n");

#if MCL_CURVETYPE!=MCL_MONTGOMERY

  printf("C448 Testing ECIES\r\n");

  P1.len=3; P1.val[0]=0x0; P1.val[1]=0x1; P1.val[2]=0x2; 
  P2.len=4; P2.val[0]=0x0; P2.val[1]=0x1; P2.val[2]=0x2; P2.val[3]=0x3; 

  M.len=17;
  for (i=0;i<=16;i++) M.val[i]=i; 

    char xstr[] = "Hello MCL ENCRYPT, this is a test";
    M.len = 20;//sizeof(xstr);
    M.val = xstr;
    MCL_CREATE_CSPRNG_C448(&RNG,&SEED);  

  printf("C448 Testing ECDSA\r\n");

  if (MCL_ECPSP_DSA_C448(MCL_HASH_TYPE_ECC,&RNG,&S0,&M,&CS,&DS)!=0) {
    printf("C448 ECDSA Signature Failed\r\n");
  }

  char tcs[]={
    0x23,0x13,0x4a,0x25,0x04,0x9c,0x45,0x58,0x0e,0xda,0xff,0xdb,0x44,0xb0,0xaa,0xd5,
    0x87,0xd0,0x64,0x16,0x5f,0x48,0x53,0x75,0x0c,0xdd,0x20,0xbf,0xa7,0x86,0x4d,0xb7,
    0x48,0x3a,0xc4,0x6c,0xee,0x78,0x31,0xaf,0x77,0xdb,0xb2,0xaa,0xc8,0xab,0xbf,0x05,
    0x2e,0x0e,0x9c,0x82,0x0c,0xf6,0xb2,0x36
  };
  char tds[]={
    0x17,0x84,0x0b,0x2f,0x5c,0x8a,0x2e,0x9a,0xa6,0x7e,0xe6,0xb1,0x77,0xc5,0x24,0xa8,
    0xdb,0x41,0x32,0x52,0xfd,0x23,0x95,0x43,0xc6,0xb1,0x10,0x5a,0xd0,0x00,0x49,0x48,
    0x36,0x9a,0x42,0x6c,0x96,0x59,0x25,0xd8,0x6c,0x5d,0x1a,0x0d,0x00,0x17,0x8f,0xc9,
    0x50,0x0c,0x0c,0x45,0x99,0x36,0x3f,0x45
  };
  CS.val = tcs;
  DS.val = tds;
  printf("C448 Signature C = 0x"); 
  MCL_OCT_output(&CS);
  printf("\r\n");
  printf("C448 Signature D = 0x"); 
  MCL_OCT_output(&DS);
  printf("\r\n");

  if (MCL_ECPVP_DSA_C448(MCL_HASH_TYPE_ECC,&W0,&M,&CS,&DS)!=0) {
    printf("C448 ECDSA Verification Failed\r\n");
  } else {
    printf("C448 ECDSA Signature/Verification succeeded \r\n");
  }
#endif

  MCL_KILL_CSPRNG_C448(&RNG);
}

static void testrsa2048()
{
  char m[MCL_RFS1],ml[MCL_RFS1],c[MCL_RFS1],e[MCL_RFS1],s[MCL_RFS1],seed[32];

  MCL_rsa_public_key_RSA2048 pub;
  MCL_rsa_private_key_RSA2048 priv;
  csprng RNG;  
  mcl_octet M={0,sizeof(m),m};
  mcl_octet ML={0,sizeof(ml),ml};
  mcl_octet C={0,sizeof(c),c};
  mcl_octet E={0,sizeof(e),e};
  mcl_octet S={0,sizeof(s),s};
  mcl_octet SEED={0,sizeof(seed),seed};

  /* fake random seed source */
  char* seedHex = "d50f4137faff934edfa309c110522f6f5c0ccb0d64e5bf4bf8ef79d1fe21031a";
  MCL_hex2bin(seedHex, SEED.val, 64);
  SEED.len=32;				

  /* initialise strong RNG */
  MCL_RSA_CREATE_CSPRNG_RSA2048(&RNG,&SEED);   

  printf("RSA2048 Generating public/private key pair\r\n");
  MCL_RSA_KEY_PAIR_RSA2048(&RNG,65537,&priv,&pub);

  printf("RSA2048 Encrypting test string\r\n");
  MCL_OCT_jstring(&M,(char *)"Hello World\n");
  /* OAEP encode message m to e  */
  MCL_OAEP_ENCODE_RSA2048(MCL_HASH_TYPE_RSA,&M,&RNG,NULL,&E); 

  /* encrypt encoded message */
  MCL_RSA_ENCRYPT_RSA2048(&pub,&E,&C);     
  printf("RSA2048 Ciphertext= "); 
  MCL_OCT_output(&C); 
  printf("\r\n");

  printf("RSA2048 Decrypting test string\r\n");
  MCL_RSA_DECRYPT_RSA2048(&priv,&C,&ML);  

  MCL_OAEP_DECODE_RSA2048(MCL_HASH_TYPE_RSA,NULL,&ML);    /* decode it */
  MCL_OCT_output_string(&ML);
  printf("\r\n");

  MCL_OCT_clear(&M); MCL_OCT_clear(&ML);   /* clean up afterwards */
  MCL_OCT_clear(&C); MCL_OCT_clear(&SEED); MCL_OCT_clear(&E); 

  printf("RSA2048 Signing message\r\n");
  MCL_PKCS15_RSA2048(MCL_HASH_TYPE_RSA,&M,&C);
  MCL_RSA_DECRYPT_RSA2048(&priv,&C,&S); /* create signature in S */ 

  printf("RSA2048 Signature= "); 
  MCL_OCT_output(&S);
  printf("\r\n");

  MCL_RSA_ENCRYPT_RSA2048(&pub,&S,&ML); 

  if (MCL_OCT_comp(&C,&ML)) {
    printf("RSA2048 Signature is valid\r\n");
  } else {
    printf("RSA2048 Signature is invalid\r\n");
  }

  MCL_RSA_KILL_CSPRNG_RSA2048(&RNG);

  MCL_RSA_PRIVATE_KEY_KILL_RSA2048(&priv);
}

int authenticate_component(int fd) {
    printf("+++++==++++++\n");
    testc25519();
    testc448();
    return 0;
}


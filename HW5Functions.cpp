//HW5 Functions . . . (provided by "The Saleh Darzi" :D)

/* ==================================================================
                        Getting LibTomMath
=====================================================================
====You Must download and install LibTomMath and ReConfigure your LibTomCrypt====
*For getting LibTomMath:
        $ git clone https://github.com/libtom/libtommath.git
        $ mkdir -p libtommath/build
        $ cd libtommath/build
        $ cmake ..
        $ make -j$(nproc)
* For reconfigureation of LibTomCrypt, go to LibTomCrypt directory:
        $ sudo make install CFLAGS="-DUSE_LTM -DLTM_DESC" EXTRALIBS="-ltommath"
*/


/*==========================================================================
                                Notes
============================================================================
* * * * *You can define each function and then use them as a solution to the HW5
        Or you can put the content of each function appropriately in your main function 
        (That's why I have provided the raw functions for you to better undestand them).

* * * * *Put this at the beggining of your main function to use LibTomMath:
        ltc_mp=ltm_desc;

* * * * *I have provided the "RSA Key Generation" and "RSA Key Export" function for completeness or if you
        liked to create your own sets of keys instead of importing my keys.
        1. You run the PRNG
        2. You create rsa_key
        3. You can export the Public Key and send it to the other side via ZeroMQ (Alice->Bob and Bob->Alice)
        4. You can use the appropriate keys for Encryption, Decryption, Signature, and Verification
*/

/*******************************
      H e a d e r s
*******************************/
#define LTM_DESC
#define USE_LTM
#include <zmq.hpp>
#include <string>
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <fstream>
#include <tomcrypt.h>
#include <string>
#include <math.h>

/****************************************************************************
                                    PRNG for Bob
*****************************************************************************/
//=====Use this function=====
prng_state Make_PRNG(prng_state *prng){
    int err;
    //PRNG
    std::string seed = "a totally secure and random string";
    if (register_prng(&fortuna_desc) == -1) {
            printf("Error registering Fortuna \n");
            exit(-1);
    }
 /* setup the PRNG */
    if ((err = rng_make_prng(128, find_prng("fortuna"), prng, NULL)) != CRYPT_OK) {
            printf("Error setting up PRNG, %s\n", error_to_string(err));
            exit(-1);
    }
    fortuna_add_entropy((const unsigned char*)seed.c_str(), seed.size(), prng);

    if (register_hash(&sha256_desc) == -1) {
            printf("Error registering sha256");
            return EXIT_FAILURE;
    }
    return *prng;
}
/****************************************************************************
                                    PRNG for Alice
*****************************************************************************/
/*
This is the first function you use before importing the keys
*/
//=====Use this function=====
prng_state Make_PRNG(prng_state *prng){
    int err;
    //PRNG
    std::string seed = "This is another string for creating prng";
    if (register_prng(&fortuna_desc) == -1) {
            printf("Error registering Fortuna \n");
            exit(-1);
    }
 /* setup the PRNG */
    if ((err = rng_make_prng(128, find_prng("fortuna"), prng, NULL)) != CRYPT_OK) {
            printf("Error setting up PRNG, %s\n", error_to_string(err));
            exit(-1);
    }
    fortuna_add_entropy((const unsigned char*)seed.c_str(), seed.size(), prng);

    if (register_hash(&sha256_desc) == -1) {
            printf("Error registering sha256");
            return EXIT_FAILURE;
    }
    return *prng;
}

/****************************************************************************
                            RSA Key Import
*****************************************************************************/
/* I have provided my set of keys in 4 files
   You can import those keys and put it in the "rsa_key key"
   Then,  Alice uses Bob's key to encrypt the message
          Alice uses her key to sign the ciphertext
          Bob uses Alice's key to verify the signature
          Bob uses his key to decrypt the ciphertex
*/
//=====Raw Functions=====
int rsa_import(unsigned char *in,
                unsigned long *inlen,
                rsa_key *key);

//=====Use this function=====
rsa_key Import_Key(unsigned char *in,/*the input key*/
                    unsigned long *inlen,/*the input key length*/
                    rsa_key *key/*the output would be stored in this data structure*/){
    int err;
    if ((err = rsa_import(in,
                          inlen,
                          key)
    ) != CRYPT_OK) {
        printf("Error in importing rsa key: %s\n", error_to_string(err));
        exit(-1);
   }
   return *key;
}

/****************************************************************************
                          RSA Encryption
****************************************************************************/
//=====Raw Function=====
int rsa_encrypt_key_ex(const unsigned char *in, 
                        unsigned long inlen, 
                        unsigned char *out, 
                        unsigned long *outlen, 
                        const unsigned char *lparam,
                        unsigned long lparamlen,
                        prng_state *prng,
                        int prng_idx,
                        int hash_idx,
                        int padding,
                        rsa_key *key);
//=====Use this function=====
void Do_RSA_Encryption(const unsigned char* in, /*The message*/
                        unsigned long inlen,/*message length*/
                        unsigned char *out, /*The ciphertext*/
                        unsigned long *outlen, /*ciphertext length*/
                        prng_state *prng, /*the utilized PRNG*/
                        rsa_key *key/*This is Bob's key*/) {
    int err;
    if ((err = rsa_encrypt_key_ex(in,
                                inlen,
                                out,
                                outlen,
                                (const unsigned char*)"SalehDarzi",
                                10,
                                prng,
                                find_prng("fortuna"),
                                find_hash("sha256"),
                                LTC_PKCS_1_OAEP,
                                key)
        ) != CRYPT_OK) {
            printf("RSA Encryption Failure %s", error_to_string(err));
            exit(-1);
}

/****************************************************************************
                            RSA Decryption
****************************************************************************/
//======Raw Functions======
int rsa_decrypt_key_ex(const unsigned char *in, 
                        unsigned long inlen, 
                        unsigned char *out, 
                        unsigned long *outlen, 
                        const unsigned char *lparam,
                        unsigned long lparamlen,
                        int hash_idx,
                        int padding,
                        int *stat,
                        rsa_key *key);
//======Use-case======
void Do_RSA_Decryption(const unsigned char *in,/*The Ciphertext*/
                        unsigned long inlen, /*ciphertext length*/
                        unsigned char *out,/*The plaintext*/
                        unsigned long *outlen,/*plaintext length*/
                        rsa_key *key/*this is Bob's key*/){
    int err;
    int stat=1;
    if ((err = rsa_decrypt_key_ex(in,
                                inlen,
                                out,
                                outlen,
                                (const unsigned char*)"SalehDarzi",
                                10,
                                find_hash("sha256"),
                                LTC_PKCS_1_OAEP,
                                &stat,
                                key)
    ) != CRYPT_OK) {
            printf("RSA Decryption Failure %s", error_to_string(err));
            exit(-1);
    }
}

/****************************************************************************
                            RSA Signature
****************************************************************************/
//=====Raw Functions=====
int rsa_sign_hash_ex(const unsigned char *in, 
                    unsigned long inlen, 
                    unsigned char *out, 
                    unsigned long *outlen, 
                    int padding,
                    prng_state *prng,
                    int prng_idx,
                    int hash_idx,
                    unsigned long saltlen,
                    rsa_key *key);
//======Use this function=====
void Do_RSA_Sign(const unsigned char *in,/*The ciphertext*/
                 unsigned long inlen,/*ciphetext length*/
                 unsigned char *out,/*The Signature*/
                 unsigned long *outlen,/*Signature length*/
                 prng_state *prng, /*This is the utilized PRNG*/
                 rsa_key *key/*This is Alice's key*/){
    int err;
    if((err = rsa_sign_hash_ex(in,
                               inlen,
                               out,
                               outlen,
                                LTC_PKCS_1_PSS,
                               prng,
                               find_prng("fortuna"),
                               find_hash("sha256"),
                               8,
                               key)
    ) != CRYPT_OK) {
            printf("RSA Signature Failure %s", error_to_string(err));
            exit(-1);
    }
}
/****************************************************************************
                            RSA Verification
****************************************************************************/
//=====Raw Functions=====
int rsa_verify_hash_ex(const unsigned char *sig,
                        unsigned long siglen,
                        const unsigned char *hash,
                        unsigned long hashlen,
                        int padding,
                        int hash_idx,
                        unsigned long saltlen,
                        int *stat,
                        rsa_key *key);

//=====Use this function=====
int* Do_RSA_Verify(const unsigned char *sig,/*The signature*/
                 unsigned long siglen, /*signature length*/
                 unsigned char *hash, /*the hash*/
                 unsigned long *hashlen, /*the hash length*/
                 int *stat; /*this is the output of you verification, [zero:fail, non-zero:pass]*/
                 rsa_key *key/*This is Alice's key*/){

    int err;
    if((err = rsa_verify_hash_ex(sig,
                                   siglen,
                                   hash,
                                   hashlen,
                                   LTC_PKCS_1_PSS,
                                   find_hash("sha256"),
                                   8,
                                   stat,
                                   key)
        ) != CRYPT_OK) {
                printf("RSA Verification Failure %s", error_to_string(err));
                exit(-1);
        }
        return *stat;
} 




/****************************************************************************
                        RSA Key Generation
****************************************************************************/
/*
You do Not need this part, unless you want to create your own 
set of keys for Alice and Bob and then they shoud transmit only their 
public keys to each other 
*/

//======Raw Functions======
int rsa_make_key(prng_state *prng,
                int wprng,
                int size,
                long e,
                rsa_key *key);

//======use this if you need======
//===1024 bit key
rsa_key Create_RSA_Key(prng_state *prng,
                         rsa_key *key){
    
    int err;
    if ((err = rsa_make_key(prng,
                          find_prng("fortuna"),
                          1024/8,
                          65537,
                          key)
    ) != CRYPT_OK) {
          printf("RSA Key Generation Failure %s", error_to_string(err));
          exit(-1);
    }
    return *key;
}

/****************************************************************************
                            RSA Key Export
*****************************************************************************/
/*
If you created your own set of keys, you can export the key into an "unsigned char"
and then you can transmit the key to Alice/Bob through ZeroMQ
Only transmit the public key. Private key must remain private!
*/
//=====Raw Functions=====
int rsa_export(unsigned char *out,
                unsigned long *outlen,
                int type,
                rsa_key *key);

//=====Use these functions if you need to=====
void Export_Public_Key(unsigned char *out,/*thie is where you store the public key*/
                                    unsigned long *outlen,/*public key length*/
                                    rsa_key *key/*the is the created key*/){
    int err;
    if ((err = rsa_export(out, 
                          outlen, 
                          PK_PUBLIC,
                          key)
        ) != CRYPT_OK) {
        printf("Error in Exporting RSA Public Key: %s\n", error_to_string(err));
        exit(-1);
   }
}
//-------------
void Export_Private_Key(unsigned char *out,/*thie is where you store the private key*/
                        unsigned long *outlen,/*private key length*/
                        rsa_key *key/*the is the created key*/){
    
    int err;                        
    if ((err = rsa_export(out,
                         outlen,
                         PK_PRIVATE,
                         key)
       ) != CRYPT_OK) {
       printf("Error in Exporting RSA Private Key: %s\n", error_to_string(err));
       exit(-1);
  }
}







 














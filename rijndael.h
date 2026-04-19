/*
 * Secure Systems Development — Assignment 2
 * AES-128 (Rijndael) public header.
 *
 * Author: Likun Fang
 * Student Number: A00049290
 *
 * Exposes the two block-level entry points, aes_encrypt_block and
 * aes_decrypt_block, the block-size enum used by the starter code,
 * and the block_access helper for pretty-printing a 4x4 state.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

typedef enum {
  AES_BLOCK_128,
  AES_BLOCK_256,
  AES_BLOCK_512
} aes_block_size_t;

unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size);

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(
    unsigned char *plaintext,
    unsigned char *key,
    aes_block_size_t block_size);
unsigned char *aes_decrypt_block(
    unsigned char *ciphertext,
    unsigned char *key,
    aes_block_size_t block_size);

#endif

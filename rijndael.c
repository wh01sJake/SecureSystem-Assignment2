/*
 * Secure Systems Development — Assignment 2
 * AES-128 (Rijndael) implementation in C.
 *
 * Author: Likun Fang
 * Student Number: A00049290
 *
 * This file contains the full AES-128 block cipher: S-box and inverse
 * S-box tables, the four round operations (SubBytes, ShiftRows,
 * MixColumns, AddRoundKey) and their inverses, the key expansion, and
 * the two public functions aes_encrypt_block / aes_decrypt_block.
 * See the accompanying report for details and testing notes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

/*
 * AES S-box (forward) — FIPS-197 §5.1.1.
 * A fixed 256-byte substitution table: the value at index i is
 * what the byte i gets replaced with during SubBytes.
 */
static const unsigned char s_box[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*
 * Inverse S-box — undoes the forward table. Used by invert_sub_bytes
 * during decryption.
 */
static const unsigned char inv_s_box[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/*
 * Round constants used by key expansion (FIPS-197 §5.2).
 * The spec numbers rounds from 1, so r_con[0] = 0x00 is a placeholder
 * we never actually index into — this way r_con[1] is the round-1
 * constant, r_con[2] is round-2, etc. Makes the expand_key code read
 * more like the spec.
 */
static const unsigned char r_con[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
  case AES_BLOCK_128:
    return 16;
  case AES_BLOCK_256:
    return 32;
  case AES_BLOCK_512:
    return 64;
  default:
    fprintf(stderr, "Invalid block size %d\n", block_size);
    exit(1);
  }
}

unsigned char block_access(unsigned char *block, size_t row, size_t col, aes_block_size_t block_size) {
  int row_len;
  switch (block_size) {
    case AES_BLOCK_128:
      row_len = 4;
      break;
    case AES_BLOCK_256:
      row_len = 8;
      break;
    case AES_BLOCK_512:
      row_len = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
      exit(1);
  }

  return block[(row * row_len) + col];
}

char *message(char n) {
  char *output = (char *)malloc(7);
  strcpy(output, "hello");
  output[5] = n;
  output[6] = 0;
  return output;
}

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  // Walk through every byte in the block and replace it with the
  // corresponding entry from the S-box. For AES-128 that's 16 bytes.
  size_t numberOfBytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < numberOfBytes; i++) {
    block[i] = s_box[block[i]];
  }
}

void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  // Each row shifts LEFT by its row index — I had this the wrong way
  // round on the first attempt. Row 0 is untouched, row 1 rotates left
  // by 1, row 2 by 2, row 3 by 3. Interesting gotcha: row 2 and row 3
  // come out looking the same in either direction so only rows 1 and 3
  // actually revealed the mistake in tests.
  unsigned char temp;

  // Row 1: rotate LEFT by 1.
  temp = block[1];
  block[1] = block[5];
  block[5] = block[9];
  block[9] = block[13];
  block[13] = temp;

  // Row 2: rotate by 2 (direction doesn't matter on 4 elements).
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Row 3: rotate LEFT by 3 (same as rotating right by 1).
  temp = block[15];
  block[15] = block[11];
  block[11] = block[7];
  block[7] = block[3];
  block[3] = temp;
}

// GF(2^8) multiplication by 2. If the top bit is set we reduce modulo
// the AES irreducible polynomial 0x1b (FIPS-197 §4.2). This is the only
// GF multiplication primitive we actually need — bigger coefficients
// like 3 are just (xtime(a) ^ a), and mix_columns composes everything
// out of these.
static unsigned char xtime(unsigned char a) {
  return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

// Mix a single 4-byte column in place. Using the reference's compact
// form of the matrix multiplication — the t/u bookkeeping avoids
// needing a separate temp array for the whole column.
static void mix_single_column(unsigned char *col) {
  unsigned char t = col[0] ^ col[1] ^ col[2] ^ col[3];
  unsigned char u = col[0];
  col[0] ^= t ^ xtime(col[0] ^ col[1]);
  col[1] ^= t ^ xtime(col[1] ^ col[2]);
  col[2] ^= t ^ xtime(col[2] ^ col[3]);
  col[3] ^= t ^ xtime(col[3] ^ u);
}

void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  // Each group of 4 consecutive bytes is a column in the AES sense,
  // because the linear byte stream fills columns first (see FIPS-197
  // §3.4). Mix them independently.
  for (size_t i = 0; i < 4; i++) {
    mix_single_column(&block[i * 4]);
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  // Same idea as sub_bytes but using the inverse table so we get the
  // original byte back during decryption.
  size_t numberOfBytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < numberOfBytes; i++) {
    block[i] = inv_s_box[block[i]];
  }
}

void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  // Inverse: rotate every row RIGHT by its index. Since I fixed
  // shift_rows to go left, this one now goes the other way to undo it.
  unsigned char temp;

  // Row 1: rotate RIGHT by 1.
  temp = block[13];
  block[13] = block[9];
  block[9] = block[5];
  block[5] = block[1];
  block[1] = temp;

  // Row 2: rotate by 2.
  temp = block[2];
  block[2] = block[10];
  block[10] = temp;
  temp = block[6];
  block[6] = block[14];
  block[14] = temp;

  // Row 3: rotate RIGHT by 3.
  temp = block[3];
  block[3] = block[7];
  block[7] = block[11];
  block[11] = block[15];
  block[15] = temp;
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  // Trick from the reference: pre-adjust each column with two
  // xtime-of-xtime xors, then run the forward mix_columns to finish.
  // This dodges having to compute the inverse matrix (with coefficients
  // 0x0E, 0x0B, 0x0D, 0x09) directly, which would be more code and
  // easier to mess up.
  for (size_t i = 0; i < 4; i++) {
    unsigned char *col = &block[i * 4];
    unsigned char u = xtime(xtime(col[0] ^ col[2]));
    unsigned char v = xtime(xtime(col[1] ^ col[3]));
    col[0] ^= u;
    col[1] ^= v;
    col[2] ^= u;
    col[3] ^= v;
  }
  mix_columns(block, block_size);
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block,
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  // AddRoundKey is literally a per-byte XOR with the round key.
  // Easiest operation in AES by a wide margin.
  size_t numberOfBytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < numberOfBytes; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  // AES-128: 11 round keys × 16 bytes = 176 bytes total.
  // Round 0 is just the cipher key verbatim. After that we derive each
  // 4-byte word from the previous one, with a schedule_core step every
  // 16 bytes (at the start of each new round key).
  unsigned char *expanded = (unsigned char *)malloc(176);
  memcpy(expanded, cipher_key, 16);

  unsigned char temp[4];

  for (size_t i = 16; i < 176; i += 4) {
    // Previous word.
    temp[0] = expanded[i - 4];
    temp[1] = expanded[i - 3];
    temp[2] = expanded[i - 2];
    temp[3] = expanded[i - 1];

    if (i % 16 == 0) {
      // RotWord: cyclic left shift by 1.
      unsigned char t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t;

      // SubWord: S-box each byte.
      temp[0] = s_box[temp[0]];
      temp[1] = s_box[temp[1]];
      temp[2] = s_box[temp[2]];
      temp[3] = s_box[temp[3]];

      // XOR first byte with the round constant. My first attempt used
      // (i/16)-1 thinking the schedule is 0-indexed — but because
      // r_con[0] is just a placeholder 0x00, I should use r_con[i/16]
      // directly. The tests caught this by reporting a 1-bit diff at
      // byte 16 of the expanded key (the exact XOR that went missing).
      temp[0] ^= r_con[i / 16];
    }

    // New word = temp XOR word 16 bytes earlier.
    expanded[i + 0] = temp[0] ^ expanded[i - 16];
    expanded[i + 1] = temp[1] ^ expanded[i - 15];
    expanded[i + 2] = temp[2] ^ expanded[i - 14];
    expanded[i + 3] = temp[3] ^ expanded[i - 13];
  }

  return expanded;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // Standard AES-128: 1 initial AddRoundKey, 9 full rounds, 1 final
  // round without MixColumns. 10 rounds total.
  unsigned char *round_keys = expand_key(key, block_size);
  unsigned char *output = (unsigned char *)malloc(16);
  memcpy(output, plaintext, 16);

  // Round 0: just XOR in the cipher key.
  add_round_key(output, &round_keys[0], block_size);

  // Rounds 1..9: full pipeline.
  for (int round = 1; round < 10; round++) {
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, &round_keys[round * 16], block_size);
  }

  // Round 10: no MixColumns.
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, &round_keys[10 * 16], block_size);

  free(round_keys);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // Decrypt runs the rounds in reverse. Start by XORing with the LAST
  // round key (round 10), then peel back round by round.
  unsigned char *round_keys = expand_key(key, block_size);
  unsigned char *output = (unsigned char *)malloc(16);
  memcpy(output, ciphertext, 16);

  add_round_key(output, &round_keys[10 * 16], block_size);

  // Rounds 9..1 in reverse order.
  for (int round = 9; round > 0; round--) {
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
    add_round_key(output, &round_keys[round * 16], block_size);
    invert_mix_columns(output, block_size);
  }

  // Final inverse round: no InvMixColumns, finishes by XORing with
  // the cipher key.
  invert_shift_rows(output, block_size);
  invert_sub_bytes(output, block_size);
  add_round_key(output, &round_keys[0], block_size);

  free(round_keys);
  return output;
}

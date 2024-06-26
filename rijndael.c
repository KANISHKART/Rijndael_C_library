/*
 -- Author      : KANISHKAR THIRUNAVUKKARASU 
 -- Student No  : D23124630
 -- Description : This code contains the core logic for AES-128 bit Encryption implemented in C.
                  Inspiration from : https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
                  Python Implementation for AES : https://github.com/boppreh/aes
 */

#include <stdlib.h>
#include <stdio.h>
#include "rijndael.h"

#define AES_ROUND 10

unsigned char s_box[256] =   {
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

unsigned char inverted_s_box[256] =   {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

unsigned char r_con[32] ={
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39
};



/*
  - Substituting the elemenets from S-BOX (s_box) lookup table from above.
  - Used during encryption process for AES
 */
void sub_bytes(unsigned char *block, int length) {
  for(int i=0;i<length;i++){
    block[i]=s_box[block[i]];
  }
}

/*
  - Substituting the elemenets from Inverted S-BOX (inverted_s_box) lookup table from above.
  - Used during decryption process for AES
 */
void invert_sub_bytes(unsigned char *block,  int length) {
   for(int i=0;i<length;i++){
    block[i]=inverted_s_box[block[i]];
  }
}

/* 
  - This function shifts the values in each row of the block, considering the block as a transposed matrix.
  - Since the block is represented as a transposed matrix, row-wise shifting corresponds to column-wise shifting in the original matrix.
  - This is used in Encryption process
*/
void shift_rows(unsigned char *block) {

  unsigned char temp;

  //Row 1
  temp=block[1];
  block[1]=block[5], block[5]=block[9], block[9]=block[13], block[13]=temp;

  //Row 2
  temp=block[2];
  block[2]=block[10], block[10]=temp;
  temp=block[6];
  block[6]=block[14], block[14]=temp;

  //Row
  temp=block[15];
  block[15]=block[11], block[11]= block[7], block[7]=block[3],block[3]=temp;

}

/* 
  - This function shifts the values in each row of the block, considering the block as a transposed matrix.
  - Since the block is represented as a transposed matrix, row-wise shifting corresponds to column-wise shifting in the original matrix.
  - This is used in Decryption process 
*/
void invert_shift_rows(unsigned char *block) {
  unsigned char temp;

  //Row 1
  temp=block[13];
  block[13]=block[9], block[9]=block[5], block[5]= block[1], block[1]=temp;

  //Row 2
  temp=block[10];
  block[10]=block[2], block[2]=temp;
  temp=block[14];
  block[14]=block[6], block[6]=temp;

  //Row 3
  temp=block[3];
   block[3]=block[7], block[7]=block[11], block[11]= block[15], block[15]= temp;
}

/* Function to perform multiplication in GF(2^8) */
unsigned char Multiply(unsigned char x, unsigned char y) {
    unsigned char result = 0;
     // Iterate until y becomes 0
    while (y) {
        // If the least significant bit of y is 1, XOR the result with x
        if (y & 0x01)
            result ^= x;
        // If the most significant bit of x is 1, left shift x and XOR with 0x1B (irreducible polynomial)
        if (x & 0x80)
            x = (x << 1) ^ 0x1B;
        else
          // Otherwise, just left shift x
            x <<= 1;
        // Right shift y to process the next bit
        y >>= 1;
    }
    return result;
}

/*

02 03 01 01
01 02 03 01
01 01 02 03
03 01 01 02  - Matrix to multiply with

Function to perform MixColumns operation in AES encryption */

void mixColumns(unsigned char *state) {
   // Temporary array to store the new state
    unsigned char temp[16];

  // Loop through each column
    for (int c = 0; c < 4; ++c) {
        //perform column mixing by using the multiply function above
        temp[4 * c + 0] = Multiply(0x02, state[4 * c + 0]) ^ Multiply(0x03, state[4 * c + 1]) ^ state[4 * c + 2] ^ state[4 * c + 3];
        temp[4 * c + 1] = state[4 * c + 0] ^ Multiply(0x02, state[4 * c + 1]) ^ Multiply(0x03, state[4 * c + 2]) ^ state[4 * c + 3];
        temp[4 * c + 2] = state[4 * c + 0] ^ state[4 * c + 1] ^ Multiply(0x02, state[4 * c + 2]) ^ Multiply(0x03, state[4 * c + 3]);
        temp[4 * c + 3] = Multiply(0x03, state[4 * c + 0]) ^ state[4 * c + 1] ^ state[4 * c + 2] ^ Multiply(0x02, state[4 * c + 3]);
    }

    // Copy the new state back to the original state
    for (int i = 0; i < 16; ++i)
        state[i] = temp[i];
}


/*
0e 0b 0d 09
09 0e 0b 0d
0d 09 0e 0b
0b 0d 09 0e

Function to perform inverse MixColumns operation in AES decryption

*/
void invert_mix_columns(unsigned char *state) {
   // Temporary array to store the new state
    unsigned char temp[16];

    // Loop through each column
    for (int c = 0; c < 4; ++c) {
       // Perform inverse column mixing
        temp[4 * c + 0] = Multiply(0x0e, state[4 * c + 0]) ^ Multiply(0x0b, state[4 * c + 1]) ^ Multiply(0x0d, state[4 * c + 2]) ^ Multiply(0x09, state[4 * c + 3]);
        temp[4 * c + 1] = Multiply(0x09, state[4 * c + 0]) ^ Multiply(0x0e, state[4 * c + 1]) ^ Multiply(0x0b, state[4 * c + 2]) ^ Multiply(0x0d, state[4 * c + 3]);
        temp[4 * c + 2] = Multiply(0x0d, state[4 * c + 0]) ^ Multiply(0x09, state[4 * c + 1]) ^ Multiply(0x0e, state[4 * c + 2]) ^ Multiply(0x0b, state[4 * c + 3]);
        temp[4 * c + 3] = Multiply(0x0b, state[4 * c + 0]) ^ Multiply(0x0d, state[4 * c + 1]) ^ Multiply(0x09, state[4 * c + 2]) ^ Multiply(0x0e, state[4 * c + 3]);
    }

    // Copy the new state back to the original state
    for (int i = 0; i < 16; ++i)
        state[i] = temp[i];
}

/*
  This operation is shared between encryption and decryption

  Function to perform AddRoundKey operation in 
  AES encryption or decryption.

  Parameters:
  - block: Pointer to the block of data to which the round key is added.
  - round_key: Pointer to the round key to be added.
  - startIndex: Index of the round key from which to start adding.
  - endIndex: Index of the round key until which to add (exclusive).
 */
void add_round_key(unsigned char *block, unsigned char *round_key, int startIndex, int endIndex) {
  int keyStart=0;
  for(int i=startIndex;i<endIndex;i++){
    // XOR
    block[keyStart]^=round_key[i];

    keyStart++;
  }
}
 
/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {

  // Setting size to accomodate 11 round keys
  unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE * 11);

  int r_con_index=1;

  // To iterate each rows
  int row=0;

  // Starting point of value
  int itr_index= BLOCK_SIZE;

  // Base pointer on last row in master key
  int lastRow=3;

  // Iterating 11 times to expand the keys
  for(int j=0;j<11;j++){

    // Copying all key to expand_key array
    if(j==0){
        for(int i=0;i<16;i++)
          output[i]=cipher_key[i];
    }

    // Expanding logic for remaining 10 keys from previous one.
    else{

      // Circular switch for ROT word i.e., last column in the current key
      char rot[4] = {BLOCK_ACCESS(output,lastRow,1),BLOCK_ACCESS(output,lastRow,2),BLOCK_ACCESS(output,lastRow,3),BLOCK_ACCESS(output,lastRow,0)};
     
      // Replacing ROT array elements from S-BOX lookup table values
      sub_bytes(rot,4);

      // Iterate each key matrix (4 X 4) here in the loop
      for(int k=0;k<4;k++){
        
        if(k==0){ // Last row ⊕ r_con_ ⊕ ROT  
          output[itr_index]   = BLOCK_ACCESS(output,row,0) ^ r_con[r_con_index++] ^ rot[0]; // r_con XOR for rest is 0 so, XOR the 1st column
          output[itr_index+1] = BLOCK_ACCESS(output,row,1) ^ rot[1];
          output[itr_index+2] = BLOCK_ACCESS(output,row,2) ^ rot[2];
          output[itr_index+3] = BLOCK_ACCESS(output,row,3) ^ rot[3];
          row+=1;
          itr_index+=4;
        }
        else{ // Previous row ⊕ similar previous key row
          output[itr_index]   = BLOCK_ACCESS(output,row,0) ^ output[itr_index-4]; 
          output[itr_index+1] = BLOCK_ACCESS(output,row,1) ^ output[itr_index-3];
          output[itr_index+2] = BLOCK_ACCESS(output,row,2) ^ output[itr_index-2];
          output[itr_index+3] = BLOCK_ACCESS(output,row,3) ^ output[itr_index-1];
    
          itr_index+=4;
          row+=1;
        }
      }

      // Updating base pointer to recently generated key 
      lastRow+=4;
    }

  }

  return output;
}

/*
  AES encryption function starts here

  Function to encrypt a single block of plaintext 
  using AES encryption algorithm.

  Parameters:
  - plaintext: Pointer to the block of plaintext data to be encrypted.
  - key: Pointer to the encryption key.

  Returns:
  - Pointer to the encrypted block of data.

  Note: The size of plaintext and key should be 128 bits (16 bytes).
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {

  // Initialize variables for managing key expansion
  int expandKey_start_index=0;
  int expandKey_last_index=16;

  // Allocate memory for the output block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  
  // Copy plaintext to output block
  for(int i=0;i< BLOCK_SIZE;i++){
    output[i]=plaintext[i];
  }

  // Expand the key
  unsigned char *exp_key = expand_key(key);

  // Add the initial round key
  add_round_key(output,key,expandKey_start_index,expandKey_last_index);
 
  //iterating 10 time as this is 128 bit 
  for(int i=1;i<AES_ROUND;i++){

    // Perform AES operations
    sub_bytes(output, BLOCK_SIZE);
    shift_rows(output);
    mixColumns(output);

    // Update key index range for the next round
    expandKey_start_index+=16;
    expandKey_last_index+=16;

    // add round key
    add_round_key(output,exp_key,expandKey_start_index,expandKey_last_index);
  }

  // Perform final round operations
  sub_bytes(output, BLOCK_SIZE);
  shift_rows(output);
  expandKey_start_index+=16;
  expandKey_last_index+=16;
  add_round_key(output,exp_key,expandKey_start_index,expandKey_last_index);

  return output; // Return the encrypted block
}

/*
  Function to decrypt a single block of ciphertext 
  using AES decryption algorithm.

  Parameters:
  - ciphertext: Pointer to the block of ciphertext data to be decrypted.
  - key: Pointer to the decryption key.

  Returns:
  - Pointer to the decrypted block of data.

  The size of ciphertext and key should be 128 bits (16 bytes).
*/
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // For managing key expansion           
  int expandKey_start_index= 160;
  int expandKey_last_index= 176;

  // Allocate memory for the output block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  
  // Copy ciphertext to output block
  for(int i=0;i< BLOCK_SIZE;i++){
    output[i]=ciphertext[i];
  }

  // Expand the key
  unsigned char *exp_key = expand_key(key);
  
  // Add the initial round key
  add_round_key(output, exp_key, expandKey_start_index, expandKey_last_index);
  
  // Perform inverse ShiftRows and SubBytes operations
  invert_shift_rows(output);
  invert_sub_bytes(output, BLOCK_SIZE);
  
  //iterating 10 time as this is 128 bit 
  for(int i=AES_ROUND;i>1;i--){
    // Update key index range for the current round starting from the last to first
    expandKey_start_index-=16;
    expandKey_last_index-=16;

    // Add the round key
    add_round_key(output,exp_key,expandKey_start_index,expandKey_last_index);
    
    // Perform inverse MixColumns, ShiftRows, and SubBytes operations
    invert_mix_columns(output);
    invert_shift_rows(output);
    invert_sub_bytes(output, BLOCK_SIZE);
  }

  // Update key index range for the final round
  expandKey_start_index-=16;
  expandKey_last_index-=16;

  // Add the final round key
  add_round_key(output,exp_key,expandKey_start_index,expandKey_last_index);

  return output;  // Return the decrypted block
}

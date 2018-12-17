/*

Created
  based on nano-ecc: https://github.com/iSECPartners/nano-ecc
by
  Nan Li @ CSIRO
  nan.li@csiro.au
*/

#ifndef NANOECC_H_
#define NANOECC_H_

#include <stdint.h>
#include <stdlib.h>

/* Define as 1 to enable ECDSA functions, 0 to disable.
 */
#define ECC_ECDSA 1

/* Optimization settings. Define as 1 to enable an optimization, 0 to disable it.
ECC_SQUARE_FUNC - If enabled, this will cause a specific function to be used for (scalar) squaring instead of the generic
                  multiplication function. Improves speed by about 8% .
*/
#define ECC_SQUARE_FUNC 1

/* Inline assembly options.
Currently we do not provide any inline assembly options. In the future we plan to offer
inline assembly for AVR and 8051.

Note: You must choose the appropriate option for your target architecture, or compilation will fail
with strange assembler messages.
*/
#define ecc_asm_none   0
#ifndef ECC_ASM
    #define ECC_ASM ecc_asm_none
#endif

/* Curve selection options. */
#define secp128r1 16
#define secp192r1 24
#define secp256r1 32
#define secp384r1 48
#ifndef ECC_CURVE
    #define ECC_CURVE secp192r1
#endif

#if (ECC_CURVE != secp128r1 && ECC_CURVE != secp192r1 && ECC_CURVE != secp256r1 && ECC_CURVE != secp384r1)
    #error "Must define ECC_CURVE to one of the available curves"
#endif

#define NUM_ECC_DIGITS ECC_CURVE

typedef struct EccPoint
{
    uint8_t x[NUM_ECC_DIGITS];
    uint8_t y[NUM_ECC_DIGITS];
} EccPoint;

/* ecc_make_key() function.
Create a public/private key pair.

You must use a new nonpredictable random number to generate each new key pair.

Outputs:
    p_publicKey  - Will be filled in with the point representing the public key.
    p_privateKey - Will be filled in with the private key.

Inputs:
    p_random - The random number to use to generate the key pair.

Returns 1 if the key pair was generated successfully, 0 if an error occurred. If 0 is returned,
try again with a different random number.
*/
int ecc_make_key(EccPoint *p_publicKey, uint8_t p_privateKey[NUM_ECC_DIGITS], uint8_t p_random[NUM_ECC_DIGITS]);

/* ecc_valid_public_key() function.
Determine whether or not a given point is on the chosen elliptic curve (ie, is a valid public key).

Inputs:
    p_publicKey - The point to check.

Returns 1 if the given point is valid, 0 if it is invalid.
*/
int ecc_valid_public_key(EccPoint *p_publicKey);


#if ECC_ECDSA
/* ecdsa_sign() function.
Generate an ECDSA signature for a given hash value.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it in to
this function along with your private key and a random number.
You must use a new nonpredictable random number to generate each new signature.

Outputs:
    r, s - Will be filled in with the signature values.

Inputs:
    p_privateKey - Your private key.
    p_random     - The random number to use to generate the signature.
    p_hash       - The message hash to sign.

Returns 1 if the signature generated successfully, 0 if an error occurred. If 0 is returned,
try again with a different random number.
*/
int ecdsa_sign(uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS], uint8_t p_privateKey[NUM_ECC_DIGITS],
    uint8_t p_random[NUM_ECC_DIGITS], uint8_t p_hash[NUM_ECC_DIGITS]);

/* ecdsa_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    p_publicKey - The signer's public key
    p_hash      - The hash of the signed data.
    r, s        - The signature values.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
int ecdsa_verify(EccPoint *p_publicKey, uint8_t p_hash[NUM_ECC_DIGITS], uint8_t r[NUM_ECC_DIGITS], uint8_t s[NUM_ECC_DIGITS]);

#endif /* ECC_ECDSA */

/* ecc_bytes2native() function.
Convert an integer in standard octet representation to the native format.

Outputs:
    p_native - Will be filled in with the native integer value.

Inputs:
    p_bytes - The standard octet representation of the integer to convert.
*/
void ecc_bytes2native(uint8_t p_native[NUM_ECC_DIGITS], uint8_t p_bytes[NUM_ECC_DIGITS*4]);

/* ecc_native2bytes() function.
Convert an integer in native format to the standard octet representation.

Outputs:
    p_bytes - Will be filled in with the standard octet representation of the integer.

Inputs:
    p_native - The native integer value to convert.
*/
void ecc_native2bytes(uint8_t p_bytes[NUM_ECC_DIGITS*4], uint8_t p_native[NUM_ECC_DIGITS]);


/* Extended Functions */
/* Extended functions are developed based on original funcations. The purpose is to make these important functions easier to use.
NegtiveNX:
	Return the negtive value of the input
Input:
	x - A big number in type of unit8_t*
Output: 
	x - Return -x mod n.
*/
void NegtiveNX(uint8_t *x);

/*
ModNInv:
	Compute the multiplicative inverse of number mod n.
Input:
	p_dest	- variable for taking the result
	p_input	- a big integer
Output:
	x	- Return -x mod n.
*/
void ModNInv(uint8_t *p_result, uint8_t *p_input);

/*
ModNAdd:
	Compute the addtion of two big integers mod n.
Input:
	p_dest	- variable for taking the result
	p_left	- the first big integer
	p_right	- the second big integer.
Output:
	p_dest	- the value of p_left + p_right mod n.
*/
void ModNAdd(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right);

/*
ModNSub:
	Compute the subtraction of two big integers mod n.
Input:
	p_dest	- variable for taking the result
	p_left	- the first big integer
	p_right	- the second big integer.
Output:
	p_dest	- the value of p_left - p_right mod n.
*/
void ModNSub(uint8_t *p_result, uint8_t *p_left, uint8_t *p_right);

/*
ModNMult:
	Compute the multiplication of two big integers mod n.
Input:
	p_dest	- variable for taking the result
	p_left	- the first big integer
	p_right	- the second big integer.
Output:
	p_dest	- the value of p_left * p_right mod n.
*/
void ModNMult(uint8_t *p_dest, uint8_t *p_left, uint8_t *p_right);

/*
EccPoint_mult:
	Compute the point multiplication of given parameters.
Input:
	p_dest	- variable for taking the result EC point
	p_point	- the base point for the calculation; if NULL - use the generator as the base point.
	p_scalar- the scalar value.
	p_initialZ - initial value of calculation, usually be NULL.
Output:
	p_dest	- the value of the new EC point p_scalar(p_piont) mod n.
*/
void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint8_t *p_scalar, uint8_t *p_initialZ);

/*
FastCompute:
	Compute tR+mQ by using Shamir's trick.
Input:
	x	- value of x-coordinate of result EC point.
	R	- the first EC point; if NULL - use the generator as the point.
	Q	- the second EC point; if NULL - use the generator as the point.
	t	- coefficient of the first point R.
	m	- coefficient of the second point Q.
Output:
	x	- value of x-coordinate of result EC point.
*/
void FastCompute(uint8_t* x, EccPoint* R, EccPoint* Q, uint8_t* t, uint8_t* m);


/*
IsGenerator:
	Check whether the given value equals to the defined generator. Note: It is not to determin whether a point is a generator of the group.
Input:
	p_point	- an EC point.
Output:
	0	- p_point equals to the generator.
	1	- p_point does not equal to the generator.
       -1	- p_point does not equal to the generator.
*/
int IsGenerator(EccPoint* p_piont);

/*
getRandomBytes:
	Generate a random big integer.
Input:
	p_dest	- variable for taking the result
	p_size	- size of the integer
Output:
	p_dest	- a random number in size of p_size.
*/
void getRandomBytes(uint8_t *p_dest, unsigned p_size);


/*
vli_cmp:
	Compare two integers.
Input:
	p_left	- the first big integer.
	p_right	- the second big ineger.
Output:
	0	- two integers are equal.
	1	- p_left > p_right.
       -1	- p_left < p_right.	
*/
int vli_cmp(uint8_t *p_left, uint8_t *p_right);

/*
GetN:
	Return the value of modulo n.
Input:
	p_dest	- variable for taking the output
Output:
	p_dest 	- current modulo n.
*/
void GetN(uint8_t* p_dest);

/*
GetP:
	Return the value of modulo p.
Input:
	p_dest	- variable for taking the output
Output:
	p_dest 	- current modulo p.
*/
void GetP(uint8_t* p_dest);

/*
GetG:
	Return the value of generator G.
Input:
	p_dest	- variable for taking the output
Output:
	p_dest 	- current generator G.
*/
void GetG(EccPoint* g_dest);


//int getRandomBytes2(void *p_dest, unsigned p_size);
#endif 



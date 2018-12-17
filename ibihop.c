/*

Created by

  Nan Li @ CSIRO
  nan.li@csiro.au

*/
#include "ibihop.h"

/* Generate a public/private key pair. */
void IBIHOP_KeyGen(EccPoint* pk, uint8_t* sk)
{
    getRandomBytes(sk, NUM_ECC_DIGITS * sizeof(uint8_t));
    ecc_make_key(pk, sk, sk);
}

/* Compute E = e^-1P */
void IBIHOP_Pass1(EccPoint* E, uint8_t* e, uint8_t* e_inv)
{  
    getRandomBytes(e, NUM_ECC_DIGITS * sizeof(uint8_t));
    ModNInv(e_inv, e);	/* e_inv*e = 1 mod n */
    EccPoint_mult(E, NULL, e_inv, NULL);	/* Use the gnerator to compute point E */
}

/* Compute R = rP */
void IBIHOP_Pass2(EccPoint* R, uint8_t* r)
{
    getRandomBytes(r, NUM_ECC_DIGITS * sizeof(uint8_t));
    EccPoint_mult(R, NULL, r, NULL);
}

/* Compute f = x[yR] + e */
void IBIHOP_Pass3(uint8_t* f, EccPoint* R, uint8_t* e, uint8_t* sk_r)
{
    EccPoint tmp;
    EccPoint_mult(&tmp, R, sk_r, NULL);
    ModNAdd(f, tmp.x, e);	/* f = tmp.x + e mod n */
}

/*
Check the validity of message 3. 
If valid: Compute the message (s = ex + r) of Pass 4 of IBIHOP protocol. 
else	: return -1.
*/
int IBIHOP_Pass4(uint8_t *s, EccPoint *pk_r, EccPoint *E, uint8_t *f, uint8_t *r, uint8_t *sk_t)
{
    uint8_t* e = (uint8_t *)malloc(NUM_ECC_DIGITS);
    EccPoint tmp;
    EccPoint_mult(&tmp, pk_r, r, NULL);	
    ModNSub(e, f, tmp.x);	/* e = f - tmp.x */
    EccPoint_mult(E, E, e, NULL);

    if (IsGenerator(E) != 0)
    {
      free(e);
      return -1;		/* Reader authentication failed. */
    }
    ModNMult(s, e, sk_t);	/* s = e * sk_t mod n */
    ModNAdd(s, r, s);		/* s = s + r mod n */
   
    free(e);
    return 0;
}

/* Check the validity of message 4 by computing e^-1(sP - R). */
int IBIHOP_TagVerf(EccPoint R, uint8_t* e_inv, uint8_t* s, EccPoint pk_t)
{
    uint8_t x[NUM_ECC_DIGITS];
    ModNMult(s, e_inv, s);	/* s = se^-1 */
    NegtiveNX(e_inv);		/* e^-1 = -e^-1 */
    FastCompute(x, &R, NULL, s, e_inv);

    if (vli_cmp(pk_t.x, x) != 0)
    {
        return -1;
    }

    return 0;
}



/*

Created by

  Nan Li @ CSIRO
  nan.li@csiro.au

This file defines the functions of IBIHOP protocol.
*/

#ifndef _IBIHOP_H_
#define _IBIHOP_H_

#include "nano-ecc.h"

/*
IBIHOP_KeyGen:
	Generate a public/private key pair.
Input:
	pk	- variable for taking the public key
	sk	- variable for taking the private key
Output:
	pk	- public key
	sk	- private key
*/
void IBIHOP_KeyGen(EccPoint* pk, uint8_t* sk);

/*
IBIHOP_Pass1:
	Compute the message (E = e^-1P) of Pass 1 of IBIHOP protocol.
Input:
	E	- variable for taking the message.
	e	- variable for taking the intermediate value which is stored for later use.
    e_inv	- variable for taking the intermediate value which is stored for later use.
Output:
	E	- meesage 1 which will be sent from reader to tag.
*/
void IBIHOP_Pass1(EccPoint* E, uint8_t* e, uint8_t* e_inv);

/*
IBIHOP_Pass2:
	Compute the message (R = rP) of Pass 2 of IBIHOP protocol.
Input:
	R	- variable for taking the message.
	r	- variable for taking the intermediate value which is stored for later use.
Output:
	R	- mesage 2 which will be sent from tag to reader.
*/
void IBIHOP_Pass2(EccPoint* R, uint8_t* r);

/*
IBIHOP_Pass3:
	Compute the message (f = x[yR] + e) of Pass 3 of IBIHOP protocol. Note that it is the optimised computation from the original IBIHOP paper.
Input:
	f	- variable for taking the message.
	R	- received R from message 2.
	e	- stored value e from IBIHOP_Pass1().
     sk_r	- reader's private key.
Output:
	f	- meesage 3 which will be sent from tag to reader.
*/
void IBIHOP_Pass3(uint8_t* f, EccPoint* R, uint8_t* e, uint8_t* sk_r);

/*
IBIHOP_Pass4:
	Check the validity of message 3. 
	If valid: Compute the message (s = ex + r) of Pass 4 of IBIHOP protocol. 
	else	: return -1.
Input:
	s	- variable for taking the message.
     pk_r	- public key of the reader.
	E	- stored value E from message 1.
	f	- received value f from message 3.
	r	- stored value r from IBIHOP_Pass2().
     sk_t	- private key of the tag.
Output:
      0,s	- meesage 4 which will be sent from tag to reader.
       -1	- if the message is invalid.
*/
int IBIHOP_Pass4(uint8_t* s, EccPoint* pk_r, EccPoint* E, uint8_t* f, uint8_t* r, uint8_t* sk_t);

/*
IBIHOP_TagVerf:
	Check the validity of message 4 by computing e^-1(sP - R).
Input:
	f	- variable for taking the message.
	R	- received value R from message 2.
    e_inv	- stored value e_inv from IBIHOP_Pass1().
	s	- rcieved value s from message 4.
     pk_t	- tag's public key.
Output:
	0	- tag is valid.
       -1	- tag is invalid.
*/
int IBIHOP_TagVerf(EccPoint R, uint8_t* e_inv, uint8_t* s, EccPoint pk_t);



#endif

/************************************************************************
  Copyright (c) IPADS@SJTU 2021. Modification to support Penglai (RISC-V TEE)
  
  This file contains GM/T SM2 standard implementation, provided by the Commercial
  Cryptography Testing Center, see <http://www.scctc.org.cn> for more infomation.

  File name:          SM2_sv.c
  Version:            SM2_sv_V1.0
  Date:               Sep 27,2016
  Description:        implementation of SM2 signature algorithm and verification algorithm
  Function List:
    1.SM2_Init                          //initiate SM2 curve
    2.Test_Point                        //test if the given point is on SM2 curve
    3.Test_PubKey                       //test if the given public key is valid
    4.Test_Zero                         //test if the big x equals zero
    5.Test_n                            //test if the big x equals n
    6.Test_Range                        //test if the big x belong to the range[1,n-1]
    7.SM2_KeyGeneration                 //generate SM2 key pair
    8.SM2_Sign                          //SM2 signature algorithm
    9.SM2_Verify                        //SM2 verification
    10.SM2_SelfCheck()                  //SM2 self-check
    11.SM3_256()                        //this function can be found in SM3.c and SM3.h
  
  Additional Functions Added By PENGLAI Enclave:
	1.MIRACL_Init						//init miracl system
	2.SM2_make_prikey					//generate a SM2 private key 
	3.SM2_make_pubkey					//generate a SM2 public Key out of a private Key
	4.SM2_gen_random					//generate a random number K lies in [1,n-1]
	5.SM2_compute_ZA					//compute ZA out of a given pubkey
**************************************************************************/

#include "sm/gm/miracl/miracl.h"
#include "sm/gm/SM2_sv.h"
#include "sm/gm/SM3.h"

#include <sm/print.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>

#define MAX_MESSAGE_SIZE 1024

const char SM2_p[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

const char SM2_a[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};

const char SM2_b[32] = {
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7,
    0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};

const char SM2_Gx[32] = {
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94,
    0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};

const char SM2_Gy[32] = {
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53,
    0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};

const char SM2_n[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23};

big Gx, Gy, p, a, b, n;
epoint *G, *nG;
char g_mem[MR_BIG_RESERVE(6)];
char g_mem_point[MR_ECP_RESERVE(2)];

static void MIRACL_Init()
{
#ifdef PENGLAI_DEBUG
	miracl *mip = mirsys(128, 16);
	printm("MIRACL: pack: %d, nib: %d, big size: %ld, point size: %ld, workspace ptr: %lx\n",
			mip->pack, mip->nib, mr_size(mip->nib-1),
			mr_esize(mr_mip->nib-1), (unsigned long)mip->workspace);
#else
	mirsys(128, 16);
#endif
}

/****************************************************************
  Function:             SM2_Init
  Description:          Initiate SM2 curve, must called before
							SM2_KeyGeneration,SM2_Sign,SM2_Verify.
  Calls:                MIRACL functions
  Called By:            SM2_SelfCheck
  Input:                null
  Output:               null
  Return:               0: success;
                        1: parameter initialization error;
                        4: the given point G is not a point of order n
  Others:
****************************************************************/
int SM2_Init()
{
	MIRACL_Init();

	sbi_memset(g_mem, 0, MR_BIG_RESERVE(6));
	Gx = mirvar_mem(g_mem, 0);
	Gy = mirvar_mem(g_mem, 1);
	p = mirvar_mem(g_mem, 2);
	a = mirvar_mem(g_mem, 3);
	b = mirvar_mem(g_mem, 4);
	n = mirvar_mem(g_mem, 5);

	bytes_to_big(SM2_NUMWORD, SM2_Gx, Gx);
	bytes_to_big(SM2_NUMWORD, SM2_Gy, Gy);
	bytes_to_big(SM2_NUMWORD, SM2_p, p);
	bytes_to_big(SM2_NUMWORD, SM2_a, a);
	bytes_to_big(SM2_NUMWORD, SM2_b, b);
	bytes_to_big(SM2_NUMWORD, SM2_n, n);

	ecurve_init(a, b, p, MR_PROJECTIVE);
	
	sbi_memset(g_mem_point, 0, MR_ECP_RESERVE(2));
	G = epoint_init_mem(g_mem_point, 0);
	nG = epoint_init_mem(g_mem_point, 1);

	if (!epoint_set(Gx, Gy, 0, G)) //initialise point G
		return ERR_ECURVE_INIT;
	ecurve_mult(n, G, nG);
	if (!point_at_infinity(nG)) //test if the order of the point is n
		return ERR_ORDER;
	
	return 0;
}

/****************************************************************
  Function:         Test_Point
  Description:      test if the given point is on SM2 curve
  Calls:
  Called By:        SM2_KeyGeneration
  Input:            point
  Output:           null
  Return:           0: success
                    3: not a valid point on curve
  Others:
****************************************************************/
int Test_Point(epoint *point)
{
	big x, y, x_3, tmp;
	char mem[MR_BIG_RESERVE(4)];
	sbi_memset(mem, 0, MR_BIG_RESERVE(4));
	x = mirvar_mem(mem, 0);
	y = mirvar_mem(mem, 1);
	x_3 = mirvar_mem(mem, 2);
	tmp = mirvar_mem(mem, 3);

	//test if y^2=x^3+ax+b
	epoint_get(point, x, y);
	power(x, 3, p, x_3); //x_3=x^3 mod p
	multiply(x, a, x);	 //x=a*x
	divide(x, p, tmp);	 //x=a*x mod p , tmp=a*x/p
	add(x_3, x, x);			 //x=x^3+ax
	add(x, b, x);				 //x=x^3+ax+b
	divide(x, p, tmp);	 //x=x^3+ax+b mod p
	power(y, 2, p, y);	 //y=y^2 mod p
	if (mr_compare(x, y) != 0)
		return ERR_NOT_VALID_POINT;

	return 0;
}

/****************************************************************
  Function:            Test_PubKey
  Description:         test if the given public key is valid
  Calls:
  Called By:           SM2_KeyGeneration
  Input:               pubKey      //a point
  Output:              null
  Return:              0: success
                       2: a point at infinity
                       5: X or Y coordinate is beyond Fq
                       3: not a valid point on curve
                       4: not a point of order n
  Others:
****************************************************************/
int Test_PubKey(epoint *pubKey)
{
	big x, y;
	epoint *nP;
	char mem[MR_BIG_RESERVE(2)];
	char mem_point[MR_ECP_RESERVE(1)];

	sbi_memset(mem, 0, MR_BIG_RESERVE(2));
	x = mirvar_mem(mem, 0);
	y = mirvar_mem(mem, 1);

	sbi_memset(mem_point, 0, MR_ECP_RESERVE(1));
	nP = epoint_init_mem(mem_point, 0);

	//test if the pubKey is the point at infinity
	if (point_at_infinity(pubKey)) // if pubKey is point at infinity, return error;
		return ERR_INFINITY_POINT;

	//test if x<p      and y<p     both hold
	epoint_get(pubKey, x, y);
	if ((mr_compare(x, p) != -1) || (mr_compare(y, p) != -1))
		return ERR_NOT_VALID_ELEMENT;

	if (Test_Point(pubKey) != 0)
		return ERR_NOT_VALID_POINT;

	//test if the order of pubKey is equal to n
	ecurve_mult(n, pubKey, nP); // nP=[n]P
	if (!point_at_infinity(nP)) // if np is point NOT at infinity, return error;
		return ERR_ORDER;

	return 0;
}

/****************************************************************
  Function:          Test_Zero
  Description:       test if the big x is zero
  Calls:
  Called By:         SM2_Sign
  Input:             pubKey      //a point
  Output:            null
  Return:            0: x!=0
                     1: x==0
  Others:
****************************************************************/
int Test_Zero(big x)
{
	big z;
	char mem[MR_BIG_RESERVE(1)];
	sbi_memset(mem, 0, MR_BIG_RESERVE(1));
	z = mirvar_mem(mem, 0);
	
	zero(z);
	if (mr_compare(x, z) == 0)
		return 1;
	return 0;
}

/****************************************************************
  Function:            Test_n
  Description:         test if the big x is order n
  Calls:
  Called By:           SM2_Sign
  Input:               big x      //a miracl data type
  Output:              null
  Return:              0: success
                       1: x==n,fail
  Others:
****************************************************************/
int Test_n(big x)
{
	if (mr_compare(x, n) == 0)
		return 1;
	return 0;
}

/****************************************************************
  Function:            Test_Range
  Description:         test if the big x belong to the range[1,n-1]
  Calls:
  Called By:           SM2_Verify
  Input:               big x      //a miracl data type
  Output:              null
  Return:              0: success
                       1: fail
  Others:
****************************************************************/
int Test_Range(big x)
{
	big one, decr_n;
	char mem[MR_BIG_RESERVE(2)];
	sbi_memset(mem, 0, MR_BIG_RESERVE(2));
	one = mirvar_mem(mem, 0);
	decr_n = mirvar_mem(mem, 1);

	convert(1, one);
	decr(n, 1, decr_n);

	if ((mr_compare(x, one) < 0) | (mr_compare(x, decr_n) > 0))
		return 1;
	return 0;
}

/* the private key, a big number lies in[1,n-2]
 * FIX ME: generate a random private key, now it's a fixed plaintext.
 */
static void SM2_make_prikey(unsigned char prikey[])
{
	unsigned char dA[32] = {
		0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1, 0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
		0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a, 0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};

	sbi_memcpy(prikey, dA, 32);
}

/****************************************************************
  Function:            SM2_make_pubkey
  Description:         calculate a pubKey out of a given priKey
  Calls:               
  Called By:           SM2_KeyGeneration()
  Input:               priKey       // a big number lies in[1,n-2]
  Output:              pubKey       // pubKey=[priKey]G
  Return:              0: success
                       2: a point at infinity
                       5: X or Y coordinate is beyond Fq
                       3: not a valid point on curve
                       4: not a point of order n
  Others:
****************************************************************/
static int SM2_make_pubkey(unsigned char PriKey[], unsigned char Px[], unsigned char Py[])
{
	int i = 0;
	big d, PAx, PAy;
	epoint *PA;
	char mem_point[MR_ECP_RESERVE(1)];
	char mem[MR_BIG_RESERVE(3)];

	sbi_memset(mem_point, 0, MR_ECP_RESERVE(1));
	PA 	= epoint_init_mem(mem_point, 0);

	sbi_memset(mem, 0, MR_BIG_RESERVE(3));
	d 	= mirvar_mem(mem, 0);
	PAx = mirvar_mem(mem, 1);
	PAy = mirvar_mem(mem, 2);

	bytes_to_big(SM2_NUMWORD, (const char *)PriKey, d);

	ecurve_mult(d, G, PA);
	epoint_get(PA, PAx, PAy);

	big_to_bytes(SM2_NUMWORD, PAx, (char *)Px, TRUE);
	big_to_bytes(SM2_NUMWORD, PAy, (char *)Py, TRUE);
	i = Test_PubKey(PA);
	if (i)
		return i;
	return 0;
}

/****************************************************************
  Function:            SM2_KeyGeneration
  Description:         generate a priKey and calculate a pubKey out of it
  Calls:               SM2_make_pubkey()
  Called By:           SM2_SelfCheck()
  Input:               priKey       // a big number lies in[1,n-2]
  Output:              pubKey       // pubKey=[priKey]G
  Return:              0: success
                       2: a point at infinity
                       5: X or Y coordinate is beyond Fq
                       3: not a valid point on curve
                       4: not a point of order n
  Others:
****************************************************************/
int SM2_KeyGeneration(unsigned char PriKey[], unsigned char Px[], unsigned char Py[])
{
	int i = 0;
	
	SM2_make_prikey(PriKey);
	i = SM2_make_pubkey(PriKey, Px, Py);
	if (i)
		return i;
	return 0;
}

/* random, a random number K lies in [1,n-1]
 * FIX ME: generate a random number, now function gen_random just generate a fixed number.
 */
static void SM2_gen_random(unsigned char rand[])
{
	unsigned char temp[32] = {
		0x59, 0x27, 0x6E, 0x27, 0xD5, 0x06, 0x86, 0x1A, 0x16, 0x68, 0x0F, 0x3A, 0xD9, 0xC0, 0x2D, 0xCC,
		0xEF, 0x3C, 0xC1, 0xFA, 0x3C, 0xDB, 0xE4, 0xCE, 0x6D, 0x54, 0xB8, 0x0D, 0xEA, 0xC1, 0xBC, 0x21};
	
	sbi_memcpy(rand, temp, 32);
}

/****************************************************************
  Function:            SM2_compute_ZA
  Description:         compute ZA out of a given pubkey
  Calls:               SM3_256()
  Called By:           SM2_Sign() SM2_Verify()
  Input:               pubKey       // pubKey=[priKey]G
  Output:              ZA           //ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
  Others:
****************************************************************/
static void SM2_compute_ZA(unsigned char ZA[], unsigned char Px[], unsigned char Py[])
{
	unsigned char Msg[210];
	unsigned char IDA[16] = {
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33,
			0x34, 0x35, 0x36, 0x37, 0x38}; //ASCII code of userA's identification
	int IDA_len = 16;
	unsigned char ENTLA[2] = {0x00, 0x80}; //the length of userA's identification,presentation in ASCII code

  	// ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA
	sbi_memcpy(Msg, ENTLA, 2);
	sbi_memcpy(Msg + 2, IDA, IDA_len);
	sbi_memcpy(Msg + 2 + IDA_len, SM2_a, SM2_NUMWORD);
	sbi_memcpy(Msg + 2 + IDA_len + SM2_NUMWORD, SM2_b, SM2_NUMWORD);
	sbi_memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 2, SM2_Gx, SM2_NUMWORD);
	sbi_memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 3, SM2_Gy, SM2_NUMWORD);
	sbi_memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 4, Px, SM2_NUMWORD);
	sbi_memcpy(Msg + 2 + IDA_len + SM2_NUMWORD * 5, Py, SM2_NUMWORD);
	SM3_256(Msg, 210, ZA);
}

/****************************************************************
  Function:            SM2_Sign
  Description:         SM2 signature algorithm
  Calls:               SM2_Init(),Test_Zero(),Test_n(), SM3_256()
  Called By:           SM2_SelfCheck()
  Input:               message     //the message to be signed
                       len         //the length of message
                       d           //the private key
  Output:              R,S         //signature result
  Return:              0: success
                       1: parameter initialization error;
                       4: the given point G is not a point of order n
                       6: the signed r equals 0 or r+rand equals n
                       7 the signed s equals 0
  Others:
****************************************************************/
int SM2_Sign(unsigned char *message, int len, unsigned char d[], unsigned char R[], unsigned char S[])
{
	unsigned char rand[32];
	unsigned char Px[32], Py[32];
	unsigned char ZA[SM3_len / 8]; // ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char M[MAX_MESSAGE_SIZE + SM3_len / 8 + 1];
	char mem[MR_BIG_RESERVE(11)];
	char mem_point[MR_ECP_RESERVE(1)];

	big dA, r, s, e, k, KGx, KGy;
	big rem, rk, z1, z2;
	epoint *KG;

	//initiate
	sbi_memset(mem, 0, MR_BIG_RESERVE(11));
	dA 	= mirvar_mem(mem, 0);
	e 	= mirvar_mem(mem, 1);
	k 	= mirvar_mem(mem, 2);
	KGx = mirvar_mem(mem, 3);
	KGy = mirvar_mem(mem, 4);
	r 	= mirvar_mem(mem, 5);
	s 	= mirvar_mem(mem, 6);
	rem = mirvar_mem(mem, 7);
	rk 	= mirvar_mem(mem, 8);
	z1 	= mirvar_mem(mem, 9);
	z2 	= mirvar_mem(mem, 10);

	bytes_to_big(SM2_NUMWORD, (const char *)d, dA); //cinstr(dA,d);

	sbi_memset(mem_point, 0, MR_ECP_RESERVE(1));
	KG 	= epoint_init_mem(mem_point, 0);

	//step1,set M=ZA||M
	sbi_memset(M, 0, MAX_MESSAGE_SIZE + SM3_len / 8 + 1);
	SM2_make_pubkey(d, Px, Py);
	SM2_compute_ZA(ZA, Px, Py);
	sbi_memcpy(M, ZA, SM3_len / 8);
	sbi_memcpy(M + SM3_len / 8, message, len);

	//step2,generate e=H(M)
	sbi_memset(hash, 0, SM3_len / 8);
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, (const char *)hash, e);

	//step3:generate k
	SM2_gen_random(rand);
	bytes_to_big(SM3_len / 8, (const char *)rand, k);

	//step4:calculate kG
	ecurve_mult(k, G, KG);

	//step5:calculate r
	epoint_get(KG, KGx, KGy);
	add(e, KGx, r);
	divide(r, n, rem);

	//judge r=0 or n+k=n?
	add(r, k, rk);
	if (Test_Zero(r) | Test_n(rk))
		return ERR_GENERATE_R;

	//step6:generate s
	incr(dA, 1, z1);
	xgcd(z1, n, z1, z1, z1);
	multiply(r, dA, z2);
	divide(z2, n, rem);
	subtract(k, z2, z2);
	add(z2, n, z2);
	multiply(z1, z2, s);
	divide(s, n, rem);

	//judge s=0?
	if (Test_Zero(s))
		return ERR_GENERATE_S;

	big_to_bytes(SM2_NUMWORD, r, (char *)R, TRUE);
	big_to_bytes(SM2_NUMWORD, s, (char *)S, TRUE);

	return 0;
}

/****************************************************************
  Function:         SM2_Verify
  Description:      SM2 verification algorithm
  Calls:            SM2_Init(),Test_Range(), Test_Zero(),SM3_256()
  Called By:        SM2_SelfCheck()
  Input:            message     //the message to be signed
                    len         //the length of message
                    Px,Py       //the public key
                    R,S         //signature result
  Output:
  Return:           0: success
                    1: parameter initialization error;
                    4: the given point G is not a point of order n
                    B: public key error
                    8: the signed R out of range [1,n-1]
                    9: the signed S out of range [1,n-1]
                    A: the intermediate data t equals 0
                    C: verification fail
  Others:
****************************************************************/
int SM2_Verify(unsigned char *message, int len, unsigned char Px[], unsigned char Py[], unsigned char R[], unsigned char S[])
{
	unsigned char ZA[SM3_len / 8]; // ZA=Hash(ENTLA|| IDA|| a|| b|| Gx || Gy || xA|| yA)
	unsigned char hash[SM3_len / 8];
	int M_len = len + SM3_len / 8;
	unsigned char M[MAX_MESSAGE_SIZE + SM3_len / 8 + 1];
	char mem[MR_BIG_RESERVE(10)];
	char mem_point[MR_ECP_RESERVE(3)];

	big PAx, PAy, r, s, e, t, rem, x1, y1;
	big RR;
	epoint *PA, *sG, *tPA;

	sbi_memset(mem, 0, MR_BIG_RESERVE(10));
	PAx = mirvar_mem(mem, 0);
	PAy = mirvar_mem(mem, 1);
	r 	= mirvar_mem(mem, 2);
	s 	= mirvar_mem(mem, 3);
	e 	= mirvar_mem(mem, 4);
	t 	= mirvar_mem(mem, 5);
	x1 	= mirvar_mem(mem, 6);
	y1 	= mirvar_mem(mem, 7);
	rem = mirvar_mem(mem, 8);
	RR 	= mirvar_mem(mem, 9);

	sbi_memset(mem_point, 0, MR_ECP_RESERVE(3));
	PA 	= epoint_init_mem(mem_point, 0);
	sG 	= epoint_init_mem(mem_point, 1);
	tPA = epoint_init_mem(mem_point, 2);

	bytes_to_big(SM2_NUMWORD, (const char *)Px, PAx);
	bytes_to_big(SM2_NUMWORD, (const char *)Py, PAy);

	bytes_to_big(SM2_NUMWORD, (const char *)R, r);
	bytes_to_big(SM2_NUMWORD, (const char *)S, s);

	if (!epoint_set(PAx, PAy, 0, PA)) //initialise public key
		return ERR_PUBKEY_INIT;

	//step1:test if r belong to [1,n-1]
	if (Test_Range(r))
		return ERR_OUTRANGE_R;

	//step2:test if s belong to [1,n-1]
	if (Test_Range(s))
		return ERR_OUTRANGE_S;

	//step3:generate M
	SM2_compute_ZA(ZA, Px, Py);
	sbi_memcpy(M, ZA, SM3_len / 8);
	sbi_memcpy(M + SM3_len / 8, message, len);

	//step4:generate e=H(M)
	SM3_256(M, M_len, hash);
	bytes_to_big(SM3_len / 8, (const char*)hash, e);

	//step5:generate t
	add(r, s, t);
	divide(t, n, rem);

	if (Test_Zero(t))
		return ERR_GENERATE_T;

	//step6:generate(x1,y1)
	ecurve_mult(s, G, sG);
	ecurve_mult(t, PA, tPA);
	ecurve_add(sG, tPA);
	epoint_get(tPA, x1, y1);

	//step7:generate RR
	add(e, x1, RR);
	divide(RR, n, rem);

	if (mr_compare(RR, r) == 0)
		return 0;

	return ERR_DATA_MEMCMP;
}

/****************************************************************
  Function:         SM2_SelfCheck
  Description:      SM2 self check
  Calls:            SM2_Init(), SM2_KeyGeneration,SM2_Sign, SM2_Verify,SM3_256()
  Called By:
  Input:
  Output:
  Return:           0: success
                    1: paremeter initialization error
                    2: a point at infinity
                    5: X or Y coordinate is beyond Fq
                    3: not a valid point on curve
                    4: not a point of order n
                    B: public key error
                    8: the signed R out of range [1,n-1]
                    9: the signed S out of range [1,n-1]
                    A: the intermediate data t equals 0
                    C: verification fail
  Others:
****************************************************************/
int SM2_SelfCheck()
{
	unsigned long sp_ptr;
	asm volatile("mv %0 ,sp" : "=r"(sp_ptr));
	printm(" - - - - SM2_SelfCheck , stack: %lx - - - - \n", sp_ptr);
	
	int temp;
	unsigned char dA[32]; // the private key
	unsigned char xA[32], yA[32]; // the public key
	unsigned char r[32], s[32]; // Signature

	unsigned char *message = (unsigned char *)"message digest"; //the message to be signed
	int len = sbi_strlen((const char *)message); //the length of message

	temp = SM2_Init();
	printm(" - - - - SM2_init finished ret %d - - - - \n", temp);
	if (temp)
		return temp;

	temp = SM2_KeyGeneration(dA, xA, yA);
	printm(" - - - - KeyGeneration finished ret %d - - - - \n", temp);
	if (temp)
		return temp;

	temp = SM2_Sign(message, len, dA, r, s);
	printm(" - - - - SM2_sign finished ret %d - - - - \n", temp);
	if (temp)
		return temp;

	temp = SM2_Verify(message, len, xA, yA, r, s);
	printm(" - - - - SM2_Verify finished ret %d - - - - \n", temp);
	if (temp)
		return temp;

	return 0;
}

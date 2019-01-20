#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <inttypes.h>
#include <sys/time.h>

#define ROTL24_16(x) ((((x) << 16) ^ ((x) >> 8)) & 0xFFFFFF)
#define ROTL24_3(x) ((((x) << 3) ^ ((x) >> 21)) & 0xFFFFFF)

#define ROTL24_8(x) ((((x) << 8) ^ ((x) >> 16)) & 0xFFFFFF)
#define ROTL24_21(x) ((((x) << 21) ^ ((x) >> 3)) & 0xFFFFFF)

#define ROTR24(x, r) ((x >> r) | (x << (24 - r))&0xFFFFFF)&0xFFFFFF

#define ENCROUND(x, y, k) (x = ROTR24(x, 8), x = (x + y)& 0xFFFFFF, x ^= k, y = ROTL24_3(y), y ^= x)
#define DECROUND(x, y, k) (y ^= x, y = ROTR24(y, 3), x ^= k, x = (x - y)&0xFFFFFF, x = ROTL24_8(x))
#define IV 0x010203040506ULL

void xor(uint32_t l[], uint32_t r[], uint32_t XORed[], int length){
  for(int i = 0; i < length; i++) {
      XORed[i] = l[i] ^ r[i];
  }
}


int print_array_uint32(uint32_t *array, int length)
{
  //printf("\nPrinting array val:");
  for (int i = 0; i < length;i++){
    printf("%x ",array[i]);
  }
  printf("\n");
  return 0;
}
void speck48_96(const uint32_t k[4], const uint32_t p[2], uint32_t c[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};

	rk[0] = k[0];

	c[0] = p[0];
	c[1] = p[1];

	/* full key schedule */
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF;
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}
//printf("CHECK\n");
	for (unsigned i = 0; i < 23; i++)
	{
		//ENCROUND(c[1],c[0],rk[i]);
		uint32_t x,y;
		x=c[1];
		y=c[0];
		x = ROTR24(x, 8); x = (x + y)& 0xFFFFFF; x ^= rk[i]; y = ROTL24_3(y); y ^= x;
		c[1]=x;
		c[0]=y;
	}

	return;
}

/* the inverse cipher */
void speck48_96_inv(const uint32_t k[4], const uint32_t c[2], uint32_t p[2])
{
	uint32_t rk[23];
	uint32_t ell[3] = {k[1], k[2], k[3]};
	rk[0] = k[0];

	p[0] = c[0];
	p[1] = c[1];
	/* full key schedule */
	for (unsigned i = 0; i < 22; i++)
	{
		uint32_t new_ell = ((ROTL24_16(ell[0]) + rk[i]) ^ i) & 0xFFFFFF;
		rk[i+1] = ROTL24_3(rk[i]) ^ new_ell;
		ell[0] = ell[1];
		ell[1] = ell[2];
		ell[2] = new_ell;
	}

  for(unsigned i = 0; i < 23; i++){
		uint32_t x,y;
		x=p[0];
		y=p[1];
		y ^= x; y = ROTR24(y, 3); x ^= rk[22-i]; x = (x - y)&0xFFFFFF; x = ROTL24_8(x);
		p[1]=y;
		p[0]=x;

}
}

/* The Davies-Meyer compression function based on speck48_96,
 * using an XOR feedforward
 * The input/output chaining value is given on a single 64-bit word, whose
 * low bits are set to the low half of the "plaintext"/"ciphertext" (p[0]/c[0])
 */
uint64_t cs48_dm(const uint32_t m[4], const uint64_t h)
{
	/* FILL ME */
	uint32_t h1[2];
	uint32_t c[2];
	uint64_t hmask0 = 0x0000000000ffffff;
    uint64_t hmask1 = 0x0000ffffff000000;
	uint64_t h2 = 0x0000000000000000;
	uint64_t temp = h;
    uint32_t temp2;
	h1[0] = (uint32_t)(temp >> 24);
    //printf("hmask0 =%" PRIx64" \n",temp >> 24);
    temp = h;
	h1[1] = (uint32_t)(temp & hmask0);
    
    temp2 = h1[0];
    h1[0] = h1[1];
    h1[1] = temp2;
    
	speck48_96(m,h1,c);
	xor(c,h1,h1,2);
    h2 = (uint64_t)h1[0] << 24 | (uint64_t)h1[1] ;
	return h2;
}

/* assumes message length is fourlen * four blocks of 24 bits store over 32
 * fourlen is on 48 bits
 * simply add one block of padding with fourlen and zeros on higher pos */
uint64_t hs48(const uint32_t *m, uint64_t fourlen, int padding, int verbose)
{
	uint64_t h = IV;
	uint32_t *mp = m;

	for (uint64_t i = 0; i < fourlen; i++)
	{
		h = cs48_dm(mp, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", i, mp[0], mp[1], mp[2], mp[3], h);
		mp += 4;
	}
	if (padding)
	{
		uint32_t pad[4];
		pad[0] = fourlen & 0xFFFFFF;
		pad[1] = (fourlen >> 24) & 0xFFFFFF;
		pad[2] = 0;
		pad[3] = 0;
		h = cs48_dm(pad, h);
		if (verbose)
			printf("@%llu : %06X %06X %06X %06X => %06llX\n", fourlen, pad[0], pad[1], pad[2], pad[3], h);
	}

	return h;
}

/* Computes the unique fixed-point for cs48_dm for the message m */
uint64_t get_cs48_dm_fp(uint32_t m[4])
{
	//uint64_t h = 0x000000000000;
	uint32_t h[2] = {0x000000, 0x000000};
	uint32_t f[2] = {0x000000, 0x000000};
	uint64_t h2 = 0x000000000000;
	uint64_t temp;
	int check = 0;

	while(check!=1){

        struct timeval tm;
        gettimeofday(&tm, NULL);
        srandom(tm.tv_sec + tm.tv_usec * 1000000ul);
		speck48_96_inv(m,h,f);
		temp = (uint64_t)h[0] << 24 | (uint64_t)h[1];
		h2 = (uint64_t)f[0] << 24 | (uint64_t)f[1];
        check++;
	}
	//printf("h2 =%" PRIx64" \n",h2);
	return h2;
}
/* Finds a two-block expandable message for hs48, using a fixed-point
 * That is, computes m1, m2 s.t. hs48_nopad(m1||m2) = hs48_nopad(m1||m2^*),
 * where hs48_nopad is hs48 with no padding */
void find_exp_mess(uint32_t m1[4], uint32_t m2[4])
{
	/* FILL ME */
}

void attack(void)
{
	/* FILL ME */
}
int test_sp48(void) {
	const uint32_t k[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
	uint32_t p[2] = {0x696874, 0x6d2073};
	const uint32_t enc2[2] = {0xb6445d,0x735e10};
	//const uint32_t enc3[2] = {0x735e10,0xb6445d};
	uint32_t c[2];
	uint32_t p2[2] = {0x000000,0x000000};
	uint32_t temp;
	speck48_96(k,p,c);
	if(c[0]==enc2[0] && c[1]==enc2[1])
	printf("test_sp48 SUCCESSFUL!\n");
	return;

}
 int test_sp48_inv(void) {
     
	 const uint32_t k[4] = {0x020100, 0x0a0908, 0x121110, 0x1a1918};
	 uint32_t p[2] = {0x696874, 0x6d2073};
	 const uint32_t enc2[2] = {0xb6445d,0x735e10};
	 const uint32_t enc3[2] = {0x735e10,0xb6445d};
	 uint32_t c[2];
	 uint32_t p2[2] = {0x000000,0x000000};
	 uint32_t temp;
	 speck48_96(k,p,c);
	 speck48_96_inv(k,enc3,p2);
	 temp = p2[0];
	 p2[0] = p2[1];
	 p2[1] = temp;

	 if(p2[0]==p[0] && p2[1]==p[1])
	 printf("test_sp48_inv SUCCESSFUL!\n");
 }

int test_cs48_dm(void){
    
	const uint32_t m[4] = {0x000000, 0x000000, 0x000000, 0x000000};//like key
	uint32_t h1[2] = {0x000000, 0x000000};
	uint64_t h = 0x000000000000;
	uint64_t h2 = 0x7fdd5a6eb248;
	h = cs48_dm(m,h);
	if (h2 == h)
		printf("test_cs48_dm SUCCESSFUL!\n");
    printf("We get from cs48_dm() =0x%" PRIx64" \n",h); 
	return;
}

int test_cs48_dm_fp(void){
    
	const uint32_t m[4] = {0x696874, 0xb6445d, 0x735e10, 0x121110};
	uint64_t fp, fp2;
    uint64_t hmask0 = 0x0000000000ffffff;
    uint64_t hmask1 = 0x0000ffffff000000;
	uint64_t h2 = 0x0000000000000000;
	fp = get_cs48_dm_fp(m);
	fp2 =cs48_dm(m,fp);
    h2 = h2 + ((fp & hmask0)<<24) + ((fp & hmask1)>>24);
    fp = h2;
	if(fp==fp2)
        printf("test_cs48_dm_fp SUCCESSFUL!\n");

	printf("From get_cs48_dm_fp(), we get =0x%" PRIx64" \n",fp);
	printf("From cs48_dm(), we get =0x%" PRIx64" \n",fp2);
}

int main(){

    test_sp48();
    //const uint32_t m[4] = {0x696874, 0xb6445d, 0x735e10, 0x121110};//like key
    test_sp48_inv();
    //0x7FDD5A6EB248ULL
    test_cs48_dm();
    //get_cs48_dm_fp(m);
    test_cs48_dm_fp();
    return 0;
}

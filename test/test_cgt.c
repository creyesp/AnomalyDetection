#include <stdio.h>
#include <stdlib.h>
#include "prng.h"
#include "cgt.h"

float zipfpar = 1.1;
float phi = 0.01;
int range = 123456;
unsigned int *exact;
int d;
int n=1000, lgn=32; 
int width=512,depth=5;
int netpos;  
int quartiles[4],max;
long long sumsq;


unsigned int * CreateStream(int length)
{
  long a,b;
  float zet;
  int i; 
  long value;
  unsigned int * stream;
  prng_type * prng;

  n=1048575;
  exact=(unsigned int *) calloc(n+1,sizeof(unsigned int));
  stream=(unsigned int *) calloc(length+1,sizeof(unsigned int));
      
  prng=prng_Init(44545,2);
  a = (long long) (prng_int(prng)% MOD);
  b = (long long) (prng_int(prng)% MOD);

  netpos=0;

  zet=zeta(length,zipfpar);

  for (i=1;i<=length;i++) 
    {
      value= 
	(hash31(a,b,((int) floor(fastzipf(zipfpar,n,zet,prng)) ))&1048575);
      exact[value]++;
      netpos++;
      stream[i]=value;
    }

  prng_Destroy(prng);  

  return(stream);

}

int main(){
	// int i;
	// int nbit = 32;
	// int sub_bucket[33];
	// int thresh = 60;
	// sub_bucket[0] = 130;
	// sub_bucket[1] = 115;
	// sub_bucket[2] = 90;
	// sub_bucket[3] = 0;
	// sub_bucket[4] = 15;
	// sub_bucket[5] = 0;
	// sub_bucket[6] = 15;
	// sub_bucket[7] = 15;
	// sub_bucket[8] = 0;
	// sub_bucket[9] = 115;
	// sub_bucket[10] = 15;
	// sub_bucket[11] = 115;
	// sub_bucket[12] = 15;
	// sub_bucket[13] = 115;
	// sub_bucket[14] = 15;
	// sub_bucket[15] = 15;
	// sub_bucket[16] = 0;
	// sub_bucket[17] = 0;
	// sub_bucket[18] = 0;
	// sub_bucket[19] = 15;
	// sub_bucket[20] = 15;
	// sub_bucket[21] = 15;
	// sub_bucket[22] = 15;
	// sub_bucket[23] = 15;
	// sub_bucket[24] = 115;
	// sub_bucket[25] = 15;
	// sub_bucket[26] = 115;
	// sub_bucket[27] = 115;
	// sub_bucket[28] = 15;
	// sub_bucket[29] = 15;
	// sub_bucket[30] = 115;
	// sub_bucket[31] = 15;
	// sub_bucket[32] = 115;

	// printf("%u\n", testCGT(sub_bucket, nbit, thresh)); 
	// loginsert(sub_bucket, 3232235877, 32, 1);
	// for( i = 0; i < 33; i++)
	// {
	// 	printf("sub_bucket[%d]=%d\n",i,sub_bucket[i]);
	// }
  int k = 0;
  int i;
  int thresh;
  unsigned int * uilist;
  unsigned int * stream;
  
  CGT_type * cgt;
  VGT_type * vgt;
  
  stream=CreateStream(range);
  thresh=floor(phi*netpos);  
  if (thresh==0) thresh=1;

  cgt = CGT_Init(width,depth,lgn);
  vgt = VGT_init(width,depth,lgn);
  
  for (i=1;i<=range;i++) 
    if (stream[i]>0)
    {
      CGT_Update(cgt,stream[i],1);  
      VGT_Update(vgt,stream[i],1);    
    }
   
  uilist=CGT_Output(cgt,vgt,thresh);
  printf("Total salida: %d\n",uilist[0]);
  for(k = 1; k <= uilist[0]; k++)
  {
  	printf("\tIP: %d\n",uilist[k]);
  }
  free(uilist);
  
  CGT_Destroy(cgt);
  VGT_Destroy(vgt);
return 0;
}


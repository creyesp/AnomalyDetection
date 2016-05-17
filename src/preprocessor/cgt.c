#include <stdlib.h>
#include <stdio.h>
#include "cgt.h"
#include "prng.h"
#include "util.h" //para usar LogMessage

void shell(unsigned long n, unsigned int a[])
{
  // A shell sort routine taken from the web
  // to sort the output of the Group Testing

  unsigned long i,j,inc;
  int v;
  inc=1;
  do {
    inc *= 3;
    inc++;
  } while (inc <= n);
  do { 
    inc /= 3;
    for ( i = inc; i <= n; i++ ) { 
      v = a[i];
      j = i;
      while ( a[j-inc] > v) {
        a[j] = a[j-inc];
        j -= inc;
        if (j < inc) break;
      }
      a[j] = v;
    }
  } while (inc > 1);
}

/*    sort array 2d     */
int comp96(const void *a, const void *b)
{
  size_t n;
  const unsigned int *a_ptr = a;
  const unsigned int *b_ptr = b;

  for (n = 0; n != 3; ++n) 
  {
    if (b_ptr[n] > a_ptr[n]) {
      return 1;
    }
    if (a_ptr[n] > b_ptr[n]) {
      return -1;
      
    }
  }
  return 0;
}


void loginsert(int *lists, unsigned int val, int length, int diff) 
{
  // add on a value of diff to the counts for item val
  int i;
  unsigned int bitmask;

  lists[0]+=diff; // add onto the overall count for the group
  bitmask = 1;

  for(i=length; i > 0; i-=1)
  {
    if ((val&bitmask)!=0) // if the lsb = 1, then add on to that group
      lists[i] += diff;
    bitmask *= 2;
  }
}

void loginsert96(int *lists, unsigned int val1, unsigned int val2, unsigned int val3, int length, int diff) 
{
  // add on a value of diff to the counts for item val
  int i;
  unsigned int bitmask, val;

  lists[0]+=diff; // add onto the overall count for the group
  bitmask = 1;
  val = val3;

  for(i=length; i > 0; i-=1)
  {
    if ((val&bitmask)!=0) // if the lsb = 1, then add on to that group
      lists[i] += diff;
    bitmask = bitmask<<1;
    if(i == 65){
      val=val2;
      bitmask=1;
    }
    if(i == 33){
      val = val1;
      bitmask=1;
    }
  }
}
/************************************************************************/
/*                                                                      */
/*  Funciones de creacion modificacion y eliminacion de estructuras CGT */
/*                                                                      */
/************************************************************************/

CGT_type * CGT_Init(int buckets, int tests, int lgn)
{
  // Create the data structure for Combinatorial Group Testing
  // Keep T tests.  Each test has buckets buckets
  // lgn is the bit depth of the items which will arrive
  // this code assumes lgn <= 32 since it manipulates unsigned ints

  int i;
  CGT_type * result;
  prng_type * prng;

  prng=prng_Init(-3254512,2);

  result=calloc(1,sizeof(CGT_type));
  if (result==NULL) exit(1);
  result->tests = tests;
  result->logn = lgn;
  result->buckets = buckets;
  result->subbuckets=1+lgn;
  result->count=0;
  result->testa=calloc(tests,sizeof(long long));
  result->testb=calloc(tests,sizeof(long long));
  // create space for the hash functions

  result->counts=calloc(buckets*tests,sizeof(int *));
  if (result->counts==NULL) exit(1); 
  // create space for the counts
  for (i=0;i<buckets*tests;i++)
    {
      result->counts[i]=calloc(result->subbuckets,sizeof(int));
      if (result->counts[i]==NULL) exit(1); 
    }
  for (i=0;i<tests;i++)
    {
      result->testa[i]=(long long) prng_int(prng);
      if (result->testa[i]<0) result->testa[i]= -result->testa[i];
      result->testb[i]=(long long) prng_int(prng);
      if (result->testb[i]<0) result->testb[i]= -result->testb[i];
      // initialise the hash functions
      // prng_int() should return a random integer
      // uniformly distributed in the range 0..2^31
    }
  
  

  prng_Destroy(prng);
  return (result);
}

//Funcion test, toma el umbral y hace las verificaciones
unsigned int testCGT(int *count, int nbit, int thresh)
{
  //count is the subbucket with #elements
  //nbit is the long of subbucket
  //thresh is the threshold for detect anomalies
  int t, tc;
  int c;
  unsigned int bit;
  unsigned int output = 0;

  if(count[0]>=thresh)  //the first test
  {
    for(c=1; c<=nbit ;c++)
    {
      tc = count[0]-count[c]; //test complemento
      t = count[c]; //test
      if( t >= thresh && tc >= thresh ) // |T{a,b,c}| = |T'{a,b,c}|, the second test
        return 0;
      if( t >= thresh ) // the third test
        bit = 1;
      if( tc >= thresh )
        bit = 0;
      output *= 2;
      output += bit; 
    }
  }
  else
    return 0;
  return output;
}

//unsigned int *testCGT96(unsigned int *result, int *count, int nbit, int thresh)
int testCGT96(unsigned int rtest[3], int *count, int nbit, int thresh)
{
  //count is the subbucket with #elements
  //nbit is the long of subbucket
  //thresh is the threshold for detect anomalies
  int t, tc;
  int c;
  unsigned int bit;
  unsigned int output = 0;
  unsigned int result[3];

  if(count[0]>=thresh)  //the first test
  {
    for(c=1; c<=nbit ;c++)
    {
      tc = count[0]-count[c]; //test complemento
      t = count[c]; //test
      if( t >= thresh && tc >= thresh ) // |T{a,b,c}| = |T'{a,b,c}|, the second test
        //return NULL;
        return 1;
      if( t >= thresh ) // the third test
        bit = 1;
      if( tc >= thresh )
        bit = 0;
      output = (output<<1);
      output += bit; 
      if(c == 32){
        result[0] = output;
        output = 0;
      }
      if(c == 64){
        result[1] = output;
        output = 0  ;      
      }
    }
    result[2] = output;
    rtest[0] = result[0];
    rtest[1] = result[1];
    rtest[2] = result[2];
  }
  else
    return 1;
    //return NULL;
  return 0;
}

void CGT_Update(CGT_type *cgt, unsigned int newitem, int diff)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash;
  int offset=0;

  cgt->count+=diff; //count all item
  for (i=0;i<cgt->tests;i++) 
    {
      hash=hash31(cgt->testa[i],cgt->testb[i],newitem);
      hash=hash % (cgt->buckets); 
      loginsert( cgt->counts[offset+hash], newitem, cgt->logn,diff );
      offset+=cgt->buckets;
    }
}
void CGT_Update96(CGT_type *cgt, unsigned int srcip, unsigned int dstip, unsigned short int srcport, unsigned short int dstport, int diff)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash, hash1,hash2,hash3;
  unsigned int ports;
  int offset=0;

  ports = (((unsigned int)srcport)<<16) + (unsigned int)dstport;
  cgt->count+=diff; //count all item
  for (i=0;i<cgt->tests;i++) 
    {
      hash1 = hash31(cgt->testa[i],cgt->testb[i],srcip);
      hash2 = hash31(cgt->testa[i],cgt->testb[i],dstip);
      hash3 = hash31(cgt->testa[i],cgt->testb[i],ports);
      hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);;
      hash = hash % (cgt->buckets); 
      loginsert96( cgt->counts[offset+hash], srcip, dstip, ports, cgt->logn,diff );
      offset+=cgt->buckets;
    }
}

unsigned int * CGT_Output(CGT_type * cgt,VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0;
  unsigned int guess=0;
  unsigned int * results;
  static unsigned int *compresults;
  unsigned long hits =0;
  int last=-1;  
  int claimed=0;  
  int testval=0;
  int pass = 0;
  int hash=0;
  
  results=calloc(cgt->tests*cgt->buckets,sizeof(unsigned int));
  if (results==NULL) exit(1); 
  // make some space for the list of results
  
  for (i=0;i<cgt->tests;i++)
    {
      for (j=0; j<cgt->buckets; j++)      
        {      
          guess=testCGT(cgt->counts[testval],cgt->logn,thresh);
          // go into the group, and see if there is a frequent item there
          // then check item does hash into that group... 
          if (guess>0) 
            {

              hash=hash31(cgt->testa[i],cgt->testb[i],guess);
              hash=hash % cgt->buckets; 
            }
          if ((guess>0) && (hash==j))
            {
              pass=1;
              for (k=0;k<cgt->tests;k++) 
                {
                  // check every hash of that item is above threshold... 
                  hash=hash31(cgt->testa[k],cgt->testb[k],guess);
                  hash=(cgt->buckets*k) + (hash % (cgt->buckets));
                  if (cgt->counts[hash][0]<thresh)
                    pass=0;
                }
              for( k = 0; k < vgt->tests; k++ ) 
              {
                hash = hash31(vgt->testa[k],vgt->testb[k],guess);
                hash = (vgt->buckets*k) + (hash % (vgt->buckets));
                if (vgt->counts[hash] < thresh)
                {
                  pass = 0;
                }
                
              }
              if (pass==1)
                { 
                  // if the item passes all the tests, then output it
                  results[hits]=guess;
                  hits++;
                }
            }
          testval++;
        }
    }
  if (hits>0)
    {
      // sort the output
      shell(hits-1,results);
      last=0; claimed=0;
      for (i=0;i<hits;i++)
        { 
          if (results[i]!=last)
            {   // For each distinct item in the output...
              claimed++;
              last=results[i];
            }
        }
      compresults=(unsigned int *) calloc(claimed+1,sizeof(unsigned int));
      compresults[0]=claimed;
      claimed=1; last=0;

      for (i=0;i<hits;i++)
        { 
          if (results[i]!=last)
            {   // For each distinct item in the output...
              compresults[claimed++]=results[i];
              last=results[i];
            }
        }      
    }
  else
    {
      compresults=(unsigned int *) malloc(sizeof(unsigned int));
      compresults[0]=0;
    }
  free(results);
  return(compresults);
}  

unsigned int ** CGT_Output96(CGT_type * cgt,VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0, outputGuess;
  unsigned int guess[3]={0,0,0};
  unsigned int **results, **compresults;
  unsigned int hits =0;
  unsigned int last[3];  
  int claimed=0;  
  int testval=0;
  int pass = 0;
  unsigned int hash,hash1,hash2,hash3;
  
  //guess = (unsigned int*)calloc(3,sizeof(unsigned int));

  results=(unsigned int**)calloc(cgt->tests*cgt->buckets,sizeof(unsigned int*));
  if (results==NULL) exit(1); 
  for(i = 0; i < cgt->tests*cgt->buckets; i++){
    results[i] = (unsigned int*)calloc(3,sizeof(unsigned int));
    if (results[i] == NULL) exit(1); 
  }
  // make some space for the list of results
  
  for (i=0;i<cgt->tests;i++)
    {
      for (j=0; j<cgt->buckets; j++)      
        {      
          //guess = testCGT96(cgt->counts[testval],cgt->logn,thresh);
          outputGuess = testCGT96(guess, cgt->counts[testval],cgt->logn,thresh);
          // go into the group, and see if there is a frequent item there
          // then check item does hash into that group... 
          if (outputGuess == 0) 
            {
              hash1 = hash31(cgt->testa[i],cgt->testb[i],guess[0]);
              hash2 = hash31(cgt->testa[i],cgt->testb[i],guess[1]);
              hash3 = hash31(cgt->testa[i],cgt->testb[i],guess[2]);
              hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
              hash = hash % cgt->buckets; 
            }
          if ((outputGuess == 0) && (hash == j))
            {
              pass=1;
              for (k=0;k<cgt->tests;k++) 
                {
                  // check every hash of that item is above threshold... 
                  hash1 = hash31(cgt->testa[k],cgt->testb[k],guess[0]);
                  hash2 = hash31(cgt->testa[k],cgt->testb[k],guess[1]);
                  hash3 = hash31(cgt->testa[k],cgt->testb[k],guess[2]);
                  hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
                  hash=(cgt->buckets*k) + (hash % (cgt->buckets));
                  if (cgt->counts[hash][0]<thresh){
                    pass=0;                  }
                }
              for( k = 0; k < vgt->tests; k++ ) 
              {
                hash1 = hash31(vgt->testa[k],vgt->testb[k],guess[0]);
                hash2 = hash31(vgt->testa[k],vgt->testb[k],guess[1]);
                hash3 = hash31(vgt->testa[k],vgt->testb[k],guess[2]);
                hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
                hash = (vgt->buckets*k) + (hash % (vgt->buckets));
                if (vgt->counts[hash] < thresh)
                {
                  pass = 0;
                }
                
              }
              if (pass==1)
                { 
                  // if the item passes all the tests, then output i
                  results[hits][0] = guess[0];
                  results[hits][1] = guess[1];
                  results[hits][2] = guess[2];
                  LogMessage("Salida de resuls  : %u.%u.%u.%u - ", results[hits][0]&0x000000ff,(results[hits][0]&0x0000ff00)>>8,(results[hits][0]&0x00ff0000)>>16,(results[hits][0]&0xff000000)>>24);
                  LogMessage("%u.%u.%u.%u - ", results[hits][1]&0x000000ff,(results[hits][1]&0x0000ff00)>>8,(results[hits][1]&0x00ff0000)>>16,(results[hits][1]&0xff000000)>>24);
                  LogMessage("%u - %u \n", (results[hits][2]&0xffff0000)>>16,results[hits][2]&0x0000ffff);
                  hits++;
                }
            }
          testval++;
        }
    }
  if (hits>0)
    {
      // sort the output

      qsort(results, cgt->tests*cgt->buckets , sizeof *results, comp96);
      for (i=0;i<hits;i++)
        { 
          if (results[i][0]!=last[0] && results[i][1]!=last[1] && results[i][2]!=last[2])
            {   // For each distinct item in the output...
              claimed++;
              last[0]=results[i][0];
              last[1]=results[i][1];
              last[2]=results[i][2];
              LogMessage("SORT  : %u.%u.%u.%u - ", results[i][0]&0x000000ff,(results[i][0]&0x0000ff00)>>8,(results[i][0]&0x00ff0000)>>16,(results[i][0]&0xff000000)>>24);
              LogMessage("%u.%u.%u.%u - ", results[i][1]&0x000000ff,(results[i][1]&0x0000ff00)>>8,(results[i][1]&0x00ff0000)>>16,(results[i][1]&0xff000000)>>24);
              LogMessage("%u - %u \n", (results[i][2]&0xffff0000)>>16,results[i][2]&0x0000ffff);
            }
        }
        LogMessage("claimed %i",claimed)
      compresults = calloc(claimed+1,sizeof(unsigned int *));
      if (compresults==NULL) exit(1);
      for(i = 0; i <= claimed; i++){
        compresults[i] = calloc(3,sizeof(unsigned int));
        if(compresults[i] == NULL) exit(1);
      } 
      compresults[0][0]=claimed;
      claimed=1; last[0]=0; last[1]=0; last[2]=0;

      for (i=0;i<hits;i++)
        { 
          if (results[i][0]!=last[0] && results[i][1]!=last[1] && results[i][2]!=last[2])
            {   // For each distinct item in the output...
              compresults[claimed][0]=results[i][0];
              compresults[claimed][1]=results[i][1];
              compresults[claimed][2]=results[i][2];
              last[0]=results[i][0];
              last[1]=results[i][1];
              last[2]=results[i][2];
              LogMessage("SORT  : %u.%u.%u.%u - ", compresults[claimed][0]&0x000000ff,(compresults[claimed][0]&0x0000ff00)>>8,(compresults[claimed][0]&0x00ff0000)>>16,(compresults[claimed][0]&0xff000000)>>24);
              LogMessage("%u.%u.%u.%u - ", compresults[claimed][1]&0x000000ff,(compresults[claimed][1]&0x0000ff00)>>8,(compresults[claimed][1]&0x00ff0000)>>16,(compresults[claimed][1]&0xff000000)>>24);
              LogMessage("%u - %u \n", (compresults[claimed][2]&0xffff0000)>>16,compresults[claimed][2]&0x0000ffff);
              claimed++;

            }
        }
    } 
  else
    {
      for(i = 0; i < cgt->tests*cgt->buckets; i++){
        free(results[i]);
      }
      free(results);
      return NULL;
    }
  for(i = 0; i < cgt->tests*cgt->buckets; i++){
    free(results[i]);
  }
  free(results);
  return(compresults);
}  

int CGT_Size(CGT_type *cgt)
{
  int size;
  size=2*cgt->tests*sizeof (long long) + 
    cgt->buckets*cgt->tests*(cgt->subbuckets*sizeof(int))+sizeof(CGT_type);
  return(size);
}

void CGT_Destroy(CGT_type * cgt)
{
  // Free all the space used
  int i;

  free(cgt->testa);
  free(cgt->testb);

  for (i=0; i<cgt->buckets;i++)
    free(cgt->counts[i]);
  free(cgt->counts);
  free (cgt);
}

/************************************************************************/
/*                                                                      */
/*  Funciones de creacion modificacion y eliminacion de estructuras CGT */
/*                                                                      */
/************************************************************************/


VGT_type * VGT_Init(int buckets, int tests)
{
  int i;
  VGT_type * verification;
  prng_type * prng;

  prng=prng_Init(-3254512,2);

  verification = calloc(1,sizeof(VGT_type));
  if(verification==NULL) exit(1);
  verification->tests = 4*tests;
  verification->buckets = 8*buckets;
  verification->count = 0;
  verification->testa = calloc(verification->tests,sizeof(long long));
  verification->testb = calloc(verification->tests,sizeof(long long));
  verification->counts = calloc(verification->buckets*verification->tests,sizeof(int));
  if(verification->counts == NULL) exit(1);

  for( i = 0; i < verification->tests; i++)
  {
  	  verification->testa[i] = (long long) prng_int(prng);
      if (verification->testa[i]<0) verification->testa[i] = -verification->testa[i];
      verification->testb[i]=(long long) prng_int(prng);
      if (verification->testb[i]<0) verification->testb[i] = -verification->testb[i];
  }

  prng_Destroy(prng);
  return (verification);
}


void VGT_Update(VGT_type *vgt, unsigned int newitem, int diff)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash;
  int offset=0;

  vgt->count+=diff; //count all item
  for (i=0;i<vgt->tests;i++) 
    {
      hash=hash31(vgt->testa[i],vgt->testb[i],newitem);
      hash=hash % (vgt->buckets); 
      vgt->counts[offset+hash] += diff;
      offset+=vgt->buckets;
    }
}


void VGT_Update96(VGT_type *vgt, unsigned int srcip, unsigned int dstip, unsigned short int srcport, unsigned short int dstport, int diff)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash,hash1,hash2,hash3;
  unsigned int ports;
  int offset=0;

  ports = (((unsigned int)srcport)<<16) + (unsigned int)dstport;
  vgt->count+=diff; //count all item
  for (i=0;i<vgt->tests;i++) 
    {
      hash1 = hash31(vgt->testa[i],vgt->testb[i],srcip);
      hash2 = hash31(vgt->testa[i],vgt->testb[i],dstip);
      hash3 = hash31(vgt->testa[i],vgt->testb[i],ports);
      hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
      hash = hash % (vgt->buckets); 
      vgt->counts[offset+hash] += diff;
      offset += vgt->buckets;
    }
}


void VGT_Destroy(VGT_type * vgt)
{
  // Free all the space used
  free(vgt->testa);
  free(vgt->testb);
  free(vgt->counts);
  free (vgt);
}
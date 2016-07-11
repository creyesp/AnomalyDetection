#include <stdlib.h>
#include <stdio.h>
#include "cgt.h"
#include "prng.h"
#include "util.h" //para usar LogMessage

int shell(const void *a, const void *b)
{
  int n = 0;
  unsigned int **a_ptr = (unsigned int **)a;
  unsigned int **b_ptr = (unsigned int **)b;
  if (b_ptr[0][n] > a_ptr[0][n]) {
    return 1;
  }
  if (a_ptr[0][n] > b_ptr[0][n]) 
  {
      return -1;
  }
  return 0;


}

/*    sort array 2d     */
int comp96(const void *a, const void *b)
{
  size_t n;
  unsigned int **a_ptr = (unsigned int **)a;
  unsigned int **b_ptr = (unsigned int **)b;
  // printf("%d %d\n",*((unsigned int*)*a_ptr),*((unsigned int*)*b_ptr));
  for (n = 0; n != 5; ++n) {
    if (b_ptr[0][n] > a_ptr[0][n]) {
      return 1;
    }
    if (a_ptr[0][n] > b_ptr[0][n]) {
      return -1;
      
    }
  }
  return 0;
}

int comp64(const void *a, const void *b)
{
  size_t n;
  unsigned int **a_ptr = (unsigned int **)a;
  unsigned int **b_ptr = (unsigned int **)b;
  // printf("%d %d\n",*((unsigned int*)*a_ptr),*((unsigned int*)*b_ptr));
  for (n = 0; n != 4; ++n) {
    if (b_ptr[0][n] > a_ptr[0][n]) {
      return 1;
    }
    if (a_ptr[0][n] > b_ptr[0][n]) {
      return -1;
      
    }
  }
  return 0;
}

void loginsert( int *lists, unsigned int val, int diff, int dsize) 
{
  // add on a value of diff to the counts for item val
  int length = 32;
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
  lists[length+1] = dsize;
}

void loginsert64( int *lists, unsigned int val1, unsigned int val2, int diff, int dsize) 
{
  // add on a value of diff to the counts for item val
  int length = 64;
  int i;
  unsigned int bitmask, val;

  lists[0]+=diff; // add onto the overall count for the group
  bitmask = 1;
  val = val2;

  for(i=length; i > 0; i-=1)
  {
    if ((val&bitmask)!=0) // if the lsb = 1, then add on to that group
      lists[i] += diff;
    bitmask = bitmask<<1;
    if(i == 33){
      val = val1;
      bitmask=1;
    }
  }
  lists[length+1] += dsize; //tamaño del paquete
}

void loginsert96( int *lists, unsigned int val1, unsigned int val2, unsigned int val3, int diff, int dsize) 
{
  // add on a value of diff to the counts for item val
  int length = 96;
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
  lists[length+1] += dsize; //tamaño del paquete
}
/************************************************************************/
/*                                                                      */
/*  Create, modify and delete CGT struct                                */
/*                                                                      */
/************************************************************************/

void CGT_Init(CGT_type ** pcgt, int buckets, int tests, int lgn)
{
  // Create the data structure for Combinatorial Group Testing
  // Keep T tests.  Each test has buckets buckets
  // lgn is the bit depth of the items which will arrive
  // this code assumes lgn <= 32 since it manipulates unsigned ints

  int i,j;
  prng_type * prng;

  prng=prng_Init(-3254512,2);

  (*pcgt)= (CGT_type *) malloc(sizeof(CGT_type));
  if ((*pcgt)==NULL) exit(1);
  (*pcgt)->tests = tests;
  (*pcgt)->logn = lgn;
  (*pcgt)->buckets = buckets;
  (*pcgt)->subbuckets = 1+lgn+1;
  (*pcgt)->count = 0;
  (*pcgt)->testa = (long *) malloc(tests*sizeof(long));
  if ((*pcgt)->testa == NULL) exit(1); 
  (*pcgt)->testb = (long *) malloc(tests*sizeof(long));
  if ((*pcgt)->testb == NULL) exit(1); 
  
  /* create space for the hash functions */
  (*pcgt)->counts=(int **)malloc(buckets*tests*sizeof(int *));
  if ((*pcgt)->counts==NULL) exit(1); 
  
  /* create space for the counts */
  for (i=0;i<buckets*tests;i++)
  {
    (*pcgt)->counts[i] = (int *)malloc((*pcgt)->subbuckets*sizeof(int));
    if ((*pcgt)->counts[i] == NULL) exit(1);

    for (j = 0; j < (*pcgt)->subbuckets; ++j)
      (*pcgt)->counts[i][j] = 0;
  }

  /* Set a random integer uniformly distributed for the hash funtion*/
  for (i = 0; i < tests; i++)
  {
    (*pcgt)->testa[i] = (long) prng_int(prng);
    if ( (*pcgt)->testa[i] < 0 ) 
      (*pcgt)->testa[i] = -(*pcgt)->testa[i];
    (*pcgt)->testb[i] = (long) prng_int(prng);
    if ( (*pcgt)->testb[i] < 0 ) 
      (*pcgt)->testb[i] = -(*pcgt)->testb[i];
  }
  
  
  prng_Destroy(prng);
}

//Funcion test, toma el umbral y hace las verificaciones
unsigned int testCGT(unsigned int rtest[1], const int *countCGT, int thresh)
{
  //countCGT is the subbucket with #elements
  //nbit is the long of subbucket
  //thresh is the threshold for detect anomalies
  int nbit = 32;
  int t, tc;
  int c;
  unsigned int bit;
  unsigned int output = 0;

  if( abs(countCGT[0]) >= thresh )  //the first test
  {
    for( c = 1; c <= nbit; c++)
    {
      tc = abs(countCGT[0]) - abs(countCGT[c]); //test complemento
      t = abs(countCGT[c]); //test
      if( t >= thresh && tc >= thresh ) // |T{a,b,c}| = |T'{a,b,c}|, the second test
      {
        rtest[0] = 0;  
        return 1;
      }   
      if( t >= thresh ) // the third test
        bit = 1;
      if( tc >= thresh )
        bit = 0;
      output *= 2;
      output += bit; 
    }
    rtest[0] = output;
  }
  else{
    rtest[0] = 0;
    return 1;
  }
  return 0;
}


unsigned int testCGT64(unsigned int rtest[2], const int *countCGT, int thresh)
{
  //countCGT is the subbucket with #elements
  //thresh is the threshold for detect anomalies
  int nbit = 64;
  int t, tc;
  int c;
  unsigned int bit;
  unsigned int output = 0;

  if( abs(countCGT[0]) >= thresh )  //the first test
  {
    for( c = 1; c <= nbit; c++)
    {
      tc = abs(countCGT[0]) - abs(countCGT[c]); //test complemento
      t = abs(countCGT[c]); //test
      if( t >= thresh && tc >= thresh ) // |T{a,b,c}| = |T'{a,b,c}|, the second test
      {
        rtest[0] = 0;
        rtest[1] = 0;
        return 1;
      }
      if( t >= thresh ) // the third test
        bit = 1;
      if( tc >= thresh )
        bit = 0;
      output = (output<<1);
      output += bit; 
      if( c == 32)
      {
        rtest[0] = output;
        output = 0;
      }
    }
    rtest[1] = output;
  }
  else
  {
    rtest[0] = 0;
    rtest[1] = 0;
    return 1;
  }
  return 0;
}

unsigned int testCGT96(unsigned int rtest[3], const int *countCGT, int thresh)
{
  //count is the subbucket with #elements
  //nbit is the long of subbucket
  //thresh is the threshold for detect anomalies
  int nbit = 96;
  int t, tc;
  int c;
  unsigned int bit;
  unsigned int output = 0;

  if( abs(countCGT[0]) >= thresh )  //the first test
  {
    for( c = 1; c <= nbit; c++)
    {
      tc = abs(countCGT[0]) - abs(countCGT[c]); //test complemento
      t = abs(countCGT[c]); //test
      if( t >= thresh && tc >= thresh ) // |T{a,b,c}| = |T'{a,b,c}|, the second test
      {
        rtest[0] = 0;
        rtest[1] = 0;
        rtest[2] = 0;
        return 1;
      }
      if( t >= thresh ) // the third test
        bit = 1;
      if( tc >= thresh )
        bit = 0;
      output = (output<<1);
      output += bit; 
      if( c == 32)
      {
        rtest[0] = output;
        output = 0;
      }
      if( c == 64)
      {
        rtest[1] = output;
        output = 0;      
      }
    }
    rtest[2] = output;
  }
  else
  {
    rtest[0] = 0;
    rtest[1] = 0;
    rtest[2] = 0;
    return 1;
  }
  return 0;
}

unsigned int CGTallocation(CGT_type *cgt, unsigned int guess[],int test, int bitSize)
{
  unsigned int hash,hash1,hash2,hash3;
  if( bitSize == 96)
  {
    hash1 = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[0]);
    hash2 = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[1]);
    hash3 = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[2]);
    hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
    hash = hash % (cgt->buckets); 
  }else if(bitSize == 64)
  {
    hash1 = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[0]);
    hash2 = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[1]);
    hash = ((hash1)<<16) + ((hash2)>>16);
    hash = hash % cgt->buckets; 
  }else if(bitSize == 32)
  {
    hash = (unsigned int) hash31(cgt->testa[test],cgt->testb[test],(long long) guess[0]);
    hash = hash % cgt->buckets; 
  }

  return hash;
}


unsigned int VGTallocation(VGT_type *vgt, unsigned int guess[],int test, int bitSize)
{
  unsigned int hash,hash1,hash2,hash3;

  if( bitSize == 96)
  {
    hash1 = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[0]);
    hash2 = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[1]);
    hash3 = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[2]);
    hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);
    hash = hash % (vgt->buckets);
  }else if(bitSize == 64)
  {
    hash1 = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[0]);
    hash2 = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[1]);
    hash = ((hash1)<<16) + ((hash2)>>16);
    hash = hash % (vgt->buckets);
  }else if(bitSize == 32)
  {
    hash = (unsigned int) hash31(vgt->testa[test],vgt->testb[test],(long long) guess[0]);
    hash = hash % (vgt->buckets);
  }

  return hash;
}

void CGT_Update( CGT_type *cgt, unsigned int newitem, int diff, int dsize)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash;
  unsigned int item[1] = {newitem};
  int offset=0;

  cgt->count+=diff; //count all item
  for (i=0;i<cgt->tests;i++) 
    {

      hash = CGTallocation(cgt, item, i, 32);
      loginsert( cgt->counts[offset+hash], newitem,diff, dsize );
      offset+=cgt->buckets;
    }
// cgt->count+=diff; //count all item
// for (i=0;i<cgt->tests;i++) 
//   {
//     hash=hash31(cgt->testa[i],cgt->testb[i],newitem);
//     hash=hash % (cgt->buckets); 
//     loginsert( cgt->counts[offset+hash], newitem,diff, dsize );
//     offset+=cgt->buckets;
//   }
}

void CGT_Update64( CGT_type *cgt, unsigned int srcip, unsigned int dstip, 
                  int diff, int dsize)
{
  // receive an update and process the groups accordingly

  int i;
  // unsigned int hash, hash1,hash2;
  unsigned int hash;
  unsigned int item[2] = {srcip, dstip};
  int offset=0;

  cgt->count+=diff; //count all item
  for (i=0;i<cgt->tests;i++) 
    {
      // hash1 = hash31(cgt->testa[i],cgt->testb[i],srcip);
      // hash2 = hash31(cgt->testa[i],cgt->testb[i],dstip);
      // hash = ((hash1)<<16) + ((hash2)>>16);
      // hash = hash % (cgt->buckets); 
      hash =  CGTallocation(cgt, item, i, 64);
      loginsert64( cgt->counts[offset+hash], srcip, dstip,diff , dsize);
      offset+=cgt->buckets;
    }
}


void CGT_Update96( CGT_type *cgt, unsigned int srcip, unsigned int dstip, 
              unsigned short int srcport, unsigned short int dstport, int diff, int dsize)
{
  // receive an update and process the groups accordingly
  int i;
  // unsigned int hash, hash1,hash2,hash3;
  unsigned int hash;
  unsigned int item[3];
  unsigned int ports;
  int offset=0;

  ports = (((unsigned int)srcport)<<16) + (unsigned int)dstport;
  item[0] = srcip;
  item[1] = dstip;
  item[2] = ports;

  cgt->count+=diff; //count all item
  for (i=0;i<cgt->tests;i++) 
    {
      // hash1 = hash31(cgt->testa[i],cgt->testb[i],srcip);
      // hash2 = hash31(cgt->testa[i],cgt->testb[i],dstip);
      // hash3 = hash31(cgt->testa[i],cgt->testb[i],ports);
      // hash = ((hash1)<<22) + (((hash2)<<22)>>10) + (((hash3)<<22)>>22);;
      // hash = hash % (cgt->buckets); 
      hash =  CGTallocation(cgt, item, i, 96);
      loginsert96( cgt->counts[offset+hash], srcip, dstip, ports,diff , dsize);
      offset+=cgt->buckets;
    }
}

int CGT_Output(unsigned int ***outList, CGT_type * cgt, VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0;
  unsigned int guess[1] = {0};
  // unsigned int guess=0;
  unsigned int ** results;
  unsigned long hits =0;
  int last=-1;  
  int claimed;  
  int testval=0;
  int pass = 0;
  int outputGuess, gVerify;

  int hash=0;

  
  results = (unsigned int**)calloc(cgt->tests*cgt->buckets,sizeof(unsigned int *));
  if (results==NULL) exit(1); 
  for( i = 0; i < cgt->tests*cgt->buckets; i++)
  {
    results[i] = (unsigned int*)calloc(3,sizeof(unsigned int));
    if(results[i] == NULL) exit(1);
  }
  // make some space for the list of results
  
  for (i=0;i<cgt->tests;i++)
  {
    for (j=0; j<cgt->buckets; j++)      
    {      
      outputGuess = testCGT(guess, cgt->counts[testval],thresh);
      // go into the group, and see if there is a frequent item there
      // then check item does hash into that group... 
// LogMessage("outputGuess %d - %u | ",outputGuess,guess[0]);
// LogMessage("i: %d j: %d, CGalloc: %u\n",i,j,CGTallocation(cgt, guess, i, 32));
      if ( (outputGuess == 0) && (j == CGTallocation(cgt, guess, i, 32)) )
      {
        pass = 1;
        for( k = 0; k < cgt->tests; k++ ) 
        {
          // check every hash of that item is above threshold... 
          gVerify = CGTallocation(cgt, guess, k, 32) + cgt->buckets*k;
          if (abs(cgt->counts[gVerify][0]) < thresh){
            pass=0;
// LogMessage("pass = 0 en cgt\n");  
          }
        }
        for( k = 0; k < vgt->tests; k++ ) 
        {
          gVerify = VGTallocation(vgt, guess, k, 32) + vgt->buckets*k;
          if (abs(vgt->counts[gVerify]) < thresh){
            pass = 0; 
// LogMessage("pass = 0 en vgt\n");
          }

        }
        if (pass==1)
        { 
          // if the item passes all the tests, then output it
          results[hits][0] = guess[0];
          results[hits][1] = (unsigned int)cgt->counts[testval][0];
          results[hits][2] = (unsigned int)(cgt->counts[testval][32+1]);
          LogMessage("RESULT  : %3u.%3u.%3u.%3u # ", results[hits][0]&0x000000ff,(results[hits][0]&0x0000ff00)>>8,(results[hits][0]&0x00ff0000)>>16,(results[hits][0]&0xff000000)>>24);
          LogMessage("%10d | %10d\n", results[hits][1],results[hits][2]);
          hits++;
        }
      }
      testval++;
// for (j=0; j<cgt->buckets; j++)      
//   {      
//     guess=testCGT(cgt->counts[testval],thresh);
//     // go into the group, and see if there is a frequent item there
//     // then check item does hash into that group... 
//     if (guess>0) 
//     {

//       hash=hash31(cgt->testa[i],cgt->testb[i],guess);
//       hash=hash % cgt->buckets; 
//     }
//     if ((guess>0) && (hash==j))
//     {
//       pass=1;
//       for (k=0;k<cgt->tests;k++) 
//       {
//         // check every hash of that item is above threshold... 
//         hash=hash31(cgt->testa[k],cgt->testb[k],guess);
//         hash=(cgt->buckets*k) + (hash % (cgt->buckets));
//         if (abs(cgt->counts[hash][0])<thresh)
//           pass=0;
//       }
//       for( k = 0; k < vgt->tests; k++ ) 
//       {
//         hash = hash31(vgt->testa[k],vgt->testb[k],guess);
//         hash = (vgt->buckets*k) + (hash % (vgt->buckets));
//         if (abs(vgt->counts[hash]) < thresh)
//         {
//           pass = 0;
//         }
        
//       }
//       if (pass==1)
//       { 
//         // if the item passes all the tests, then output it
//         results[hits][0] = guess;
//         results[hits][1] = (unsigned int)cgt->counts[testval][0];
//         results[hits][2] = (unsigned int)(cgt->counts[testval][32+1]);
//         // LogMessage("RESULT  : %3u.%3u.%3u.%3u # ", results[hits][0]&0x000000ff,(results[hits][0]&0x0000ff00)>>8,(results[hits][0]&0x00ff0000)>>16,(results[hits][0]&0xff000000)>>24);
//         // LogMessage("%10d | %10d\n", results[hits][1],results[hits][2]);
//         hits++;
//       }
//     }
//     testval++;
    }
  }
  if (hits>0)
    {
      // sort the output
      qsort(results, cgt->tests*cgt->buckets , sizeof *results, shell);
      last=0; claimed=0;
      for (i=0;i<hits;i++)
        { 
          if (results[i][0]!=last)
            {   // For each distinct item in the output...
              claimed++;
              last=results[i][0];
              // LogMessage("Sort  : %3u.%3u.%3u.%3u # ", results[i][0]&0x000000ff,(results[i][0]&0x0000ff00)>>8,(results[i][0]&0x00ff0000)>>16,(results[i][0]&0xff000000)>>24);
              // LogMessage("%10d | %10d\n", results[i][1],results[i][2]);
            }
        }
      // LogMessage("Claimed %d\n",claimed);
      (*outList) = (unsigned int**)calloc(claimed+1,sizeof(unsigned int *));
      if( (*outList) == NULL ) exit(1);
      for(i = 0; i <= claimed; i++){
        (*outList)[i] = (unsigned int*)calloc(3,sizeof(unsigned int));
        if((*outList)[i] == NULL) exit(1);
      }

      claimed=1; last=0;

      for (i=0;i<hits;i++)
        { 
          if (results[i][0]!=last)
            {   // For each distinct item in the output...
              (*outList)[claimed][0]=results[i][0];
              (*outList)[claimed][1]=results[i][1];
              (*outList)[claimed][2]=results[i][2];
              last=results[i][0];

              LogMessage("Sort  : %3u.%3u.%3u.%3u (%10u)# ", (*outList)[claimed][0]&0x000000ff,((*outList)[claimed][0]&0x0000ff00)>>8,((*outList)[claimed][0]&0x00ff0000)>>16,((*outList)[claimed][0]&0xff000000)>>24,(*outList)[claimed][0]);
              LogMessage("%10d | %10d\n", (*outList)[claimed][1],(*outList)[claimed][2]);
              claimed++;
            }
        }
      (*outList)[0][0] = claimed;
      (*outList)[0][1] = 3;   
    }
  else
    {
      for(i = 0; i < cgt->tests*cgt->buckets; i++){
        free(results[i]);
      }
      free(results);
      (*outList) = NULL;
      return -1;
    }

  for(i = 0; i < cgt->tests*cgt->buckets; i++){
    free(results[i]);
  }
  free(results);
  return 0;
}  


int CGT_Output64(unsigned int *** outList, CGT_type * cgt, VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0, outputGuess;
  unsigned int guess[2]={0,0};
  unsigned int **results;
  unsigned int hits =0;
  unsigned int last[2];  
  int claimed=0;  
  int testval=0;
  int pass = 0;
  // unsigned int hash,hash1,hash2;
  int gVerify;


  results=(unsigned int**)calloc(cgt->tests*cgt->buckets,sizeof(unsigned int*));
  if (results==NULL) exit(1); 
  for(i = 0; i < cgt->tests*cgt->buckets; i++)
  {
    results[i] = (unsigned int*)calloc(4,sizeof(unsigned int));
    if (results[i] == NULL) exit(1); 
  }
  // make some space for the list of results
  
  for (i=0;i<cgt->tests;i++)
  {
    for (j=0; j<cgt->buckets; j++)      
    {      
      //guess = testCGT96(cgt->counts[testval],cgt->logn,thresh);
      outputGuess = testCGT64(guess, cgt->counts[testval],thresh);
      // go into the group, and see if there is a frequent item there
      // then check item does hash into that group... 
      if ( (outputGuess == 0) && (j == CGTallocation(cgt, guess, i, 64)) )
      {
        pass = 1;
        for( k = 0; k < cgt->tests; k++ ) 
        {
          // check every hash of that item is above threshold... 
          gVerify = CGTallocation(cgt, guess, k, 64) + cgt->buckets*k;
          if (abs(cgt->counts[gVerify][0]) < thresh)
            pass=0;  
        }
        for( k = 0; k < vgt->tests; k++ ) 
        {
          gVerify = VGTallocation(vgt, guess, k, 64) + vgt->buckets*k;
          if (abs(vgt->counts[gVerify]) < thresh)
            pass = 0;
        }
        if (pass==1)
        { 
          // if the item passes all the tests, then output i
          results[hits][0] = guess[0];
          results[hits][1] = guess[1];
          results[hits][2] = (unsigned int)cgt->counts[testval][0];
          results[hits][3] = (unsigned int)(cgt->counts[testval][64+1]);
          // LogMessage("Salida de resuls  : %3u.%3u.%3u.%3u - ", results[hits][0]&0x000000ff,(results[hits][0]&0x0000ff00)>>8,(results[hits][0]&0x00ff0000)>>16,(results[hits][0]&0xff000000)>>24);
          // LogMessage("%3u.%3u.%3u.%3u - ", results[hits][1]&0x000000ff,(results[hits][1]&0x0000ff00)>>8,(results[hits][1]&0x00ff0000)>>16,(results[hits][1]&0xff000000)>>24);
          // LogMessage("%d - %d\n", results[hits][2], results[hits][3]);
          hits++;
        }
      }
      testval++;
    }
  }
  if (hits>0)
  {
    // sort the output
    qsort(results, cgt->tests*cgt->buckets , sizeof *results, comp64);
    for (i=0;i<hits;i++)
    { 
      if (results[i][0]!=last[0] || results[i][1]!=last[1])
      {   // For each distinct item in the output...
        claimed++;
        last[0]=results[i][0];
        last[1]=results[i][1];
        // LogMessage("SORT  : %u.%u.%u.%u - ", results[i][0]&0x000000ff,(results[i][0]&0x0000ff00)>>8,(results[i][0]&0x00ff0000)>>16,(results[i][0]&0xff000000)>>24);
        // LogMessage("%u.%u.%u.%u - ", results[i][1]&0x000000ff,(results[i][1]&0x0000ff00)>>8,(results[i][1]&0x00ff0000)>>16,(results[i][1]&0xff000000)>>24);
        // LogMessage("%d - %d \n", results[i][2],results[i][3]);
      }
    }
    
    (*outList) = (unsigned int**)calloc(claimed+1,sizeof(unsigned int *));
    if ((*outList)==NULL) exit(1);
    for(i = 0; i <= claimed; i++)
    {
      (*outList)[i] = (unsigned int*)calloc(4,sizeof(unsigned int));
      if((*outList)[i] == NULL) exit(1);
    } 

    claimed=1; last[0]=0; last[1]=0; //last[2]=1 es porque en el caso de IPSD los puertos son ceros

    for (i=0;i<hits;i++)
    { 
      if (results[i][0]!=last[0] && results[i][1]!=last[1])
      {   // For each distinct item in the output...
        (*outList)[claimed][0]=results[i][0];
        (*outList)[claimed][1]=results[i][1];
        (*outList)[claimed][2]=results[i][2];
        (*outList)[claimed][3]=results[i][3];
        last[0]=results[i][0];
        last[1]=results[i][1];

        // LogMessage("Result  : %3u.%3u.%3u.%3u | ", compresults[claimed][0]&0x000000ff,(compresults[claimed][0]&0x0000ff00)>>8,(compresults[claimed][0]&0x00ff0000)>>16,(compresults[claimed][0]&0xff000000)>>24);
        // LogMessage("%3u.%3u.%3u.%3u | ", compresults[claimed][1]&0x000000ff,(compresults[claimed][1]&0x0000ff00)>>8,(compresults[claimed][1]&0x00ff0000)>>16,(compresults[claimed][1]&0xff000000)>>24);
        // LogMessage("%10d | %10d\n", compresults[claimed][2],compresults[claimed][3]);
        claimed++;
      }
    }
    (*outList)[0][0]=claimed;
    (*outList)[0][1]=4;
    // LogMessage("Claimed %d\n",compresults[0][0]);  
  } 
  else
  {
    for(i = 0; i < cgt->tests*cgt->buckets; i++)
    {
      free(results[i]);
    }
    free(results);
    (*outList) = NULL;
    return -1;
  }

  for(i = 0; i < cgt->tests*cgt->buckets; i++)
  {
    free(results[i]);
  }
  free(results);
  return 0;
}  


int CGT_Output96( unsigned int *** outList, CGT_type * cgt, VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0, outputGuess;
  unsigned int guess[3]={0,0,0};
  unsigned int hits =0;
  unsigned int last[3];  
  unsigned int **results;
  int claimed=0;  
  int testval=0;
  int pass = 0;
  // unsigned int hash,hash1,hash2,hash3;
  int gVerify;
  
  /* Make some space for the list of results */
  results = (unsigned int**) calloc(cgt->tests*cgt->buckets,sizeof(unsigned int*));
  if (results == NULL) exit(1);
  
  for(i = 0; i < cgt->tests*cgt->buckets; i++){
    results[i] = (unsigned int*)calloc(5,sizeof(unsigned int));
    if (results[i] == NULL) exit(1); 
  }
  
  
  for (i=0;i<cgt->tests;i++)
    {
      for (j=0; j<cgt->buckets; j++)      
        {      
          //guess = testCGT96(cgt->counts[testval],cgt->logn,thresh);
          outputGuess = testCGT96(guess, cgt->counts[testval],thresh);
          // go into the group, and see if there is a frequent item there
          // then check item does hash into that group... 
          if ( (outputGuess == 0) && (j == CGTallocation(cgt, guess, i, 96)) )
            {
              pass = 1;
              for ( k = 0; k < cgt->tests; k++ ) 
              {
                // check every hash of that item is above threshold... 
                gVerify = CGTallocation(cgt, guess, k, 96) + cgt->buckets*k;
                if (abs(cgt->counts[gVerify][0]) < thresh)
                  pass=0;  
              }
              for( k = 0; k < vgt->tests; k++ ) 
              {
                gVerify = VGTallocation(vgt, guess, k, 96) + vgt->buckets*k;
                if (abs(vgt->counts[gVerify]) < thresh)
                  pass = 0;
              }
              if (pass==1)
                { 
                  // if the item passes all the tests, then output i
                  results[hits][0] = guess[0];
                  results[hits][1] = guess[1];
                  results[hits][2] = guess[2];
                  results[hits][3] = (unsigned int)cgt->counts[testval][0];
                  results[hits][4] = (unsigned int)(cgt->counts[testval][cgt->logn+1]);
                  // LogMessage("Salida de resuls  : %3u.%3u.%3u.%3u - ", results[hits][0]&0x000000ff,(results[hits][0]&0x0000ff00)>>8,(results[hits][0]&0x00ff0000)>>16,(results[hits][0]&0xff000000)>>24);
                  // LogMessage("%3u.%3u.%3u.%3u - ", results[hits][1]&0x000000ff,(results[hits][1]&0x0000ff00)>>8,(results[hits][1]&0x00ff0000)>>16,(results[hits][1]&0xff000000)>>24);
                  // LogMessage("%11d - %11d ", (results[hits][2]&0xffff0000)>>16,results[hits][2]&0x0000ffff);
                  // LogMessage("%11lld - %11lld | %d - %d\n", cgt->counts[testval][0], cgt->counts[testval][cgt->logn+1]/cgt->counts[testval][0], results[hits][3], results[hits][4]);
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
          if (results[i][0]!=last[0] || results[i][1]!=last[1] || results[i][2]!=last[2])
            {   // For each distinct item in the output...
              claimed++;
              last[0]=results[i][0];
              last[1]=results[i][1];
              last[2]=results[i][2];
              // LogMessage("SORT  : %u.%u.%u.%u - ", results[i][0]&0x000000ff,(results[i][0]&0x0000ff00)>>8,(results[i][0]&0x00ff0000)>>16,(results[i][0]&0xff000000)>>24);
              // LogMessage("%u.%u.%u.%u - ", results[i][1]&0x000000ff,(results[i][1]&0x0000ff00)>>8,(results[i][1]&0x00ff0000)>>16,(results[i][1]&0xff000000)>>24);
              // LogMessage("%u - %u #", (results[i][2]&0xffff0000)>>16,results[i][2]&0x0000ffff);
              // LogMessage("%d - %d \n", results[i][3],results[i][4]);
            }
        }
      (*outList) = (unsigned int**)calloc(claimed+1,sizeof(unsigned int *));
      if ((*outList)==NULL) exit(1);
      for(i = 0; i <= claimed; i++){
        (*outList)[i] = (unsigned int*)calloc(5,sizeof(unsigned int));
        if((*outList)[i] == NULL) exit(1);
      } 

      claimed=1; last[0]=0; last[1]=0; last[2]=1; //last[2]=1 es porque en el caso de IPSD los puertos son ceros

      for (i=0;i<hits;i++)
        { 
          if (results[i][0]!=last[0] && results[i][1]!=last[1] && results[i][2]!=last[2])
            {   // For each distinct item in the output...
              (*outList)[claimed][0]=results[i][0];
              (*outList)[claimed][1]=results[i][1];
              (*outList)[claimed][2]=results[i][2];
              (*outList)[claimed][3]=results[i][3];
              (*outList)[claimed][4]=results[i][4];
              last[0]=results[i][0];
              last[1]=results[i][1];
              last[2]=results[i][2];

              // LogMessage("Result  : %3u.%3u.%3u.%3u | ", compresults[claimed][0]&0x000000ff,(compresults[claimed][0]&0x0000ff00)>>8,(compresults[claimed][0]&0x00ff0000)>>16,(compresults[claimed][0]&0xff000000)>>24);
              // LogMessage("%3u.%3u.%3u.%3u | ", compresults[claimed][1]&0x000000ff,(compresults[claimed][1]&0x0000ff00)>>8,(compresults[claimed][1]&0x00ff0000)>>16,(compresults[claimed][1]&0xff000000)>>24);
              // LogMessage("%5u | %5u # ", (compresults[claimed][2]&0xffff0000)>>16,compresults[claimed][2]&0x0000ffff);
              // LogMessage("%10d | %10d\n", compresults[claimed][3],compresults[claimed][4]);
              claimed++;
            }
        }
        (*outList)[0][0]=claimed;
        (*outList)[0][1]=5;
        // LogMessage("Claimed %d\n",compresults[0][0]);  
    } 
  else
    {
      for(i = 0; i < cgt->tests*cgt->buckets; i++){
        free(results[i]);
      }
      free(results);
      (*outList) = NULL;
      return -1;
    }
  for(i = 0; i < cgt->tests*cgt->buckets; i++){
    free(results[i]);
  }
  free(results);
  return 0;
  // return(compresults);
}  


void CGT_Destroy(CGT_type * pcgt)
{
  int i;
  if (pcgt != NULL)
  {
    int bucket = pcgt->buckets*pcgt->tests; 
    if(pcgt->testa != NULL)
    {
      free(pcgt->testa);
      pcgt->testa = NULL;
    }
    if(pcgt->testb != NULL)
    {
      free(pcgt->testb);
      pcgt->testb = NULL;
    }
    for (i=0; i < bucket; i++)
    {
      if(pcgt->counts[i] != NULL)
      {
        free(pcgt->counts[i]);
        pcgt->counts[i] = NULL;
      }
    }
    if(pcgt->counts != NULL)
    {
      free(pcgt->counts);
      pcgt->counts = NULL;
    }
    free(pcgt);
    pcgt = NULL;
  }
}

/************************************************************************/
/*                                                                      */
/*  Funciones de creacion modificacion y eliminacion de estructuras CGT */
/*                                                                      */
/************************************************************************/


void VGT_Init(VGT_type **pvgt, int buckets, int tests)
{
  int i,j;
  prng_type * prng;

  prng=prng_Init(-3254512,2);

  (*pvgt) = (VGT_type *)malloc(sizeof(VGT_type));
  if((*pvgt)==NULL) exit(1);
  (*pvgt)->tests = 4*tests;
  (*pvgt)->buckets = 8*buckets;
  (*pvgt)->count = 0;
  (*pvgt)->testa = ( long *)malloc((*pvgt)->tests*sizeof( long));
  if((*pvgt)->testa == NULL) exit(1);
  (*pvgt)->testb = ( long *)malloc((*pvgt)->tests*sizeof( long));
  if((*pvgt)->testb == NULL) exit(1);
  (*pvgt)->counts = (int *)malloc(((*pvgt)->buckets*(*pvgt)->tests)*sizeof(int));
  if((*pvgt)->counts == NULL) exit(1);
  for (j = 0; j < (*pvgt)->buckets*(*pvgt)->tests; j++)
  {
    (*pvgt)->counts[j]=0;
  }

  for( i = 0; i < (*pvgt)->tests; i++)
  {
      (*pvgt)->testa[i] = ( long) prng_int(prng);
      if ((*pvgt)->testa[i]<0) (*pvgt)->testa[i] = -(*pvgt)->testa[i];
      (*pvgt)->testb[i]=( long) prng_int(prng);
      if ((*pvgt)->testb[i]<0) (*pvgt)->testb[i] = -(*pvgt)->testb[i];
  }
  prng_Destroy(prng);
}


void VGT_Update( VGT_type *vgt, unsigned int newitem, int diff)
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

void VGT_Update64( VGT_type *vgt, unsigned int srcip, unsigned int dstip, int diff)
{
  // receive an update and process the groups accordingly

  int i;
  unsigned int hash,hash1,hash2;
  int offset=0;

  vgt->count+=diff; //count all item
  for (i=0;i<vgt->tests;i++) 
    {
      hash1 = hash31(vgt->testa[i],vgt->testb[i],srcip);
      hash2 = hash31(vgt->testa[i],vgt->testb[i],dstip);
      hash = ((hash1)<<16) + ((hash2)>>16);
      hash = hash % (vgt->buckets); 
      vgt->counts[offset+hash] += diff;
      offset += vgt->buckets;
    }
}

void VGT_Update96( VGT_type *vgt, unsigned int srcip, unsigned int dstip, unsigned short int srcport, unsigned short int dstport, int diff)
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


void VGT_Destroy(VGT_type * pvgt)
{  
  if (pvgt != NULL)
  {    
    if(pvgt->testa != NULL)
    {
      free(pvgt->testa);
      pvgt->testa = NULL;
    }    
    if(pvgt->testb != NULL)
    {
      free(pvgt->testb);
      pvgt->testb = NULL;
    }
    if(pvgt->counts != NULL)
    {      
      free(pvgt->counts);
      pvgt->counts = NULL;
    }    
    free(pvgt);
    pvgt = NULL;    
  }
}

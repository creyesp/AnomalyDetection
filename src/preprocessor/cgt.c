#include <stdlib.h>
#include <stdio.h>
#include "cgt.h"
#include "prng.h"

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

VGT_type * VGT_Init(int buckets, int tests, int lgn)
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
    for (i=inc;i<=n;i++) { 
      v=a[i];
      j=i;
      while (a[j-inc] > v) {
	a[j]=a[j-inc];
	j -= inc;
	if (j < inc) break;
      }
      a[j]=v;
    }
  } while (inc > 1);
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
	unsigned int output;

	if(count[0]>=thresh)	//the first test
	{
		for(c=1; c<=nbit ;c++)
		{
			tc = count[0]-count[c]; //test complemento
			t = count[c];	//test
			if( t >= thresh && tc >= thresh )	// |T{a,b,c}| = |T'{a,b,c}|, the second test
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

unsigned int * CGT_Output(CGT_type * cgt,VGT_type * vgt, int thresh)
{
  // Find the hot items by doing the group testing

  int i=0,j=0,k=0;
  unsigned int guess=0;
  unsigned int * results, *compresults;
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
              LogMessage("output %d: %u",i,results[i]);
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

void VGT_Destroy(VGT_type * vgt)
{
  // Free all the space used
  free(vgt->testa);
  free(vgt->testb);
  free(vgt->counts);
  free (vgt);
}
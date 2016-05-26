// cgt.h -- header file for Combinatorial Group Testing, Graham Cormode
// 2002,2003
//modified by - Cesar Reyes 2016

typedef struct CGT_type{
  int tests;
  int logn;
  int buckets;
  int subbuckets;
  long long count;
  long long ** counts;
  long long *testa, *testb;
} CGT_type;

typedef struct VGT_type{
  int tests;
  int buckets;
  long long count;
  long long * counts;
  long long  *testa, *testb;
} VGT_type;

extern CGT_type * CGT_Init(int, int, int);
extern void CGT_Update(CGT_type *, unsigned int, int); 
extern unsigned int * CGT_Output(CGT_type *, VGT_type *, long long);
extern void CGT_Update96(CGT_type *, unsigned int,unsigned int,unsigned short int,unsigned short int, int,int); 
extern unsigned int ** CGT_Output96(CGT_type *, VGT_type *, long long);
extern int CGT_Size(CGT_type *);
extern void CGT_Destroy(CGT_type *);

extern VGT_type * VGT_Init(int, int);
extern void VGT_Update(VGT_type *, unsigned int, int);
extern void VGT_Update96(VGT_type *, unsigned int,unsigned int,unsigned short int,unsigned short int, int);
extern void VGT_Destroy(VGT_type *);


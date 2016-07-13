// cgt.h -- header file for Combinatorial Group Testing, Graham Cormode
// 2002,2003
//modified by - Cesar Reyes 2016

typedef struct CGT_type{
  int tests;
  int logn;
  int buckets;
  int subbuckets;
  int count;
  int ** counts;
  long  *testa, *testb;
} CGT_type;

typedef struct VGT_type{
  int tests;
  int buckets;
  int count;
  int * counts;
  long   *testa, *testb;
} VGT_type;

// extern CGT_type * CGT_Init(int, int, int);
extern void CGT_Init(CGT_type **, int, int, int);
extern void CGT_Update( CGT_type *, unsigned int, int,int); 
extern void CGT_Update64( CGT_type *, unsigned int,unsigned int, int,int); 
extern void CGT_Update96( CGT_type *, unsigned int,unsigned int,unsigned short int,unsigned short int, int,int); 
extern int CGT_Output( unsigned int ***, CGT_type *, VGT_type *, int);
extern int CGT_Output64( unsigned int ***, CGT_type *, VGT_type *, int);
extern int CGT_Output96( unsigned int ***, CGT_type *, VGT_type *, int);
extern void CGT_Destroy(CGT_type *);

extern void VGT_Init(VGT_type **,int, int);
extern void VGT_Update( VGT_type *, unsigned int, int);
extern void VGT_Update64( VGT_type *, unsigned int,unsigned int, int);
extern void VGT_Update96( VGT_type *, unsigned int,unsigned int,unsigned short int,unsigned short int, int);
extern void VGT_Destroy(VGT_type *);


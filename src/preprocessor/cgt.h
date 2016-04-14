// cgt.h -- header file for Combinatorial Group Testing, Graham Cormode
// 2002,2003

typedef struct CGT_type{
  int tests;
  int logn;
  int buckets;
  int subbuckets;
  int count;
  int ** counts;
  int *testa, *testb;
} CGT_type;

typedef struct VGT_type{
  int tests;
  int buckets;
  int count;
  int * counts;
  int *testa, *testb;
} VGT_type;

extern CGT_type * CGT_Init(int, int, int);
extern VGT_type * VGT_Init(int, int, int);
extern void CGT_Update(CGT_type *, unsigned int, int); 
extern void VGT_Update(VGT_type *, unsigned int, int); 
extern unsigned int * CGT_Output(CGT_type *, VGT_type *, int);
extern void CGT_Destroy(CGT_type *);
extern void VGT_Destroy(VGT_type *);
extern int CGT_Size(CGT_type *);

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <immintrin.h>

typedef void (*gen_t)(uint32_t, uint32_t, uint16_t*);
typedef __m256i (*f_t)(__m256i, const void*);

static uint8_t *BASE;
static gen_t gen; static f_t F;
static uint16_t CONSTV[16], INITV[16];

static inline uint16_t rotl16(uint16_t x,int n){return (uint16_t)((x<<n)|(x>>(16-n)));}
static inline uint16_t rotr16(uint16_t x,int n){return (uint16_t)((x>>n)|(x<<(16-n)));}
static inline uint16_t unxr(uint16_t y,int sh){uint16_t x=y;for(int s=sh;s<16;s+=sh)x^=(uint16_t)(y>>s);return x;}
static uint16_t fwd(uint16_t s,const uint16_t*k,uint16_t c){for(int i=0;i<8;i++){s=(uint16_t)(s^(s>>5));uint16_t t=rotl16(s,3);s=(uint16_t)(k[i]+c+t);s=(uint16_t)(s^(s>>7));s=rotl16(s,9);}return s;}
static uint16_t finv(uint16_t s,const uint16_t*k,uint16_t c){
  for(int i=7;i>=0;i--){s=rotr16(s,9);s=unxr(s,7);uint16_t u=(uint16_t)(s-k[i]-c);uint16_t v=rotr16(u,3);s=unxr(v,5);}
  return s;
}
static int cmp64(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return x<y?-1:(x>y?1:0);}

int main(int argc,char**argv){
  FILE*f=fopen("encryptor","rb"); fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
  uint8_t*buf=malloc(n); if(fread(buf,1,n,f)!=(size_t)n)return 1; fclose(f);
  BASE=mmap((void*)0x10000000,0x8000,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
  if(BASE==MAP_FAILED){perror("mmap");return 1;}
  memcpy(BASE+0x8e0,buf+0x8e0,0x1c0);
  memcpy(BASE+0x1b70,buf+0xb70,0x660);
  free(buf);
  gen=(gen_t)(BASE+0x1c60); F=(f_t)(BASE+0x1cc0);
  memcpy(CONSTV,BASE+0xa60,32); memcpy(INITV,BASE+0xa80,32);

  uint8_t target[32];
  FILE*t=fopen("cipher.bin","rb"); if(fread(target,1,32,t)!=32)return 1; fclose(t);

  /* --- validate scalar fwd vs binary F, and inv --- */
  __m256i init=_mm256_loadu_si256((const __m256i*)BASE+  (0xa80/32*0));
  init=_mm256_loadu_si256((const __m256i*)(BASE+0xa80));
  {
    uint16_t k[8]; gen(0x123456,0x31415926,k);
    __m256i r=F(init,k); _mm256_zeroupper();
    uint16_t rv[16]; _mm256_storeu_si256((__m256i*)rv,r);
    int bad=0; for(int l=0;l<16;l++) if(rv[l]!=fwd(INITV[l],k,CONSTV[l])) bad++;
    printf("[check] scalar fwd vs binary F: %d/16 lanes differ\n",bad);
    int bad2=0; for(int l=0;l<16;l++){uint16_t a=fwd(INITV[l],k,CONSTV[l]); if(finv(a,k,CONSTV[l])!=INITV[l]) bad2++;}
    printf("[check] finv roundtrip: %d/16 bad\n",bad2);
  }

  /* --- forward table: X -> lane0,1,(lane2&0xff) packed with X --- */
  const uint32_t N=1u<<24;
  uint64_t *tab=malloc((size_t)N*8);
  if(!tab){printf("OOM\n");return 1;}
  for(uint32_t X=0;X<N;X++){
    uint16_t k1[8]; gen(X,0x31415926,k1);
    __m256i r=F(init,k1); _mm256_zeroupper();
    uint16_t rv[16]; _mm256_storeu_si256((__m256i*)rv,r);
    uint64_t k40=(uint64_t)rv[0] | ((uint64_t)rv[1]<<16) | ((uint64_t)(rv[2]&0xff)<<32);
    tab[X]=(k40<<24)|X;
  }
  fprintf(stderr,"[fwd] table built, sorting...\n");
  qsort(tab,N,8,cmp64);
  fprintf(stderr,"[fwd] sorted\n");

  /* --- backward: Y -> required mid state lanes --- */
  for(uint32_t Y=0;Y<N;Y++){
    uint16_t k2[8]; gen(Y,0x27182818,k2);
    uint16_t c0=CONSTV[0],c1=CONSTV[1],c2=CONSTV[2];
    uint16_t m0=finv(((uint16_t*)target)[0],k2,c0);
    uint16_t m1=finv(((uint16_t*)target)[1],k2,c1);
    uint16_t m2=finv(((uint16_t*)target)[2],k2,c2);
    uint64_t k40=(uint64_t)m0|((uint64_t)m1<<16)|((uint64_t)(m2&0xff)<<32);
    uint64_t lo=k40<<24, hi=((k40+1)<<24);
    uint64_t *p=(uint64_t*)bsearch(&lo,tab,N,8,cmp64);
    if(!p){ /* find first >= lo via linear-ish: use bsearch miss -> do own lower_bound */
      uint32_t a=0,b=N; while(a<b){uint32_t m=(a+b)/2; if(tab[m]<lo)a=m+1; else b=m;} p=&tab[a];
    } else {
      uint32_t a=0,b=N; while(a<b){uint32_t m=(a+b)/2; if(tab[m]<lo)a=m+1; else b=m;} p=&tab[a];
    }
    for(uint64_t *q=p; q<tab+N && *q < hi; q++){
      uint32_t Xcand=(uint32_t)(*q & 0xffffff);
      /* full verify */
      uint16_t kk1[8],kk2[8]; gen(Xcand,0x31415926,kk1); gen(Y,0x27182818,kk2);
      __m256i s=F(init,kk1); s=F(s,kk2); _mm256_zeroupper();
      uint8_t o[32]; _mm256_storeu_si256((__m256i*)o,s);
      if(!memcmp(o,target,32)){
        printf("HIT X=%06X Y=%06X  -> flag{%07X_%07X}\n",Xcand,Y,Xcand,Y);
        printf("  lowercase: flag{%07x_%07x}\n",Xcand,Y);
      }
    }
  }
  printf("done\n");
  return 0;
}

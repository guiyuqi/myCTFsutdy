#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <immintrin.h>

typedef void (*gen_t)(uint32_t, uint32_t, uint16_t*);
typedef __m256i (*f_t)(__m256i, const void*);

static uint8_t *load_code(const char *path, uint8_t **base_out){
    FILE*f=fopen(path,"rb"); if(!f){perror("open");exit(1);}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t*buf=malloc(n); if(fread(buf,1,n,f)!=(size_t)n){exit(1);} fclose(f);
    uint8_t*base=mmap((void*)0x10000000, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    if(base==MAP_FAILED){perror("mmap");exit(1);}
    memcpy(base+0x8e0, buf+0x8e0, 0x1c0);   /* .rodata  VMA==fileoff */
    memcpy(base+0x1b70, buf+0xb70, 0x660);  /* .text   fileoff = VMA-0x1000 */
    free(buf);
    *base_out=base;
    return base;
}

int main(int argc,char**argv){
    uint8_t*base;
    load_code("encryptor",&base);
    gen_t gen=(gen_t)(base+0x1c60);
    f_t   F  =(f_t)(base+0x1cc0);

    /* ---- validate end-to-end: flag{0000000_0000000} ---- */
    uint16_t k1[8],k2[8];
    gen(0x0000000,0x31415926,k1);
    gen(0x0000000,0x27182818,k2);
    printf("k1:"); for(int i=0;i<8;i++)printf(" %04x",k1[i]); printf("\n");
    printf("k2:"); for(int i=0;i<8;i++)printf(" %04x",k2[i]); printf("\n");
    __m256i st=_mm256_loadu_si256((const __m256i*)(base+0xa80));
    st=F(st,k1); st=F(st,k2);
    _mm256_zeroupper();
    uint16_t out[16]; _mm256_storeu_si256((__m256i*)out,st);
    printf("binary-model ct: "); for(int i=0;i<16;i++)printf("%02x%02x",((uint8_t*)out)[2*i],((uint8_t*)out)[2*i+1]); printf("\n");
    printf("real ct        : ");
    FILE*g=fopen("cipher_zero.bin","rb");
    if(!g){ /* regenerate */ }
    return 0;
}

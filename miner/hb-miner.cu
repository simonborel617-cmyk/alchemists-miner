// hb-miner.cu — GPU SHA-256 miner for the Alchemists mine (Robinhood Chain). Derived from the Hash Broker miner;
// the preimage is byte-identical: msg(84) = miner(20) || nonce_uint256_BE(32) || challenge(32), digest = SHA-256(msg),
// work = leading zero bits of the digest. The miner never sees keys, only public addresses.
//
//   nvcc -O3 -arch=sm_86 hb-miner.cu -o hb-miner        (see setup_vast.sh for the multi-arch build)
//   ./hb-miner --selftest
//   ./hb-miner --addr 0x<40hex> --challenge 0x<64hex> --benchsecs 20      // bench GH/s (floor unreachable)
//   ./hb-miner --addr 0x<40hex> --challenge 0x<64hex> --floor 32          // one-shot: print the first nonce >= floor
//   ./hb-miner --persist [--addr 0x<40hex>]                               // orchestrator mode, line protocol on stdin/stdout:
//       PARAMS <challenge> <floor> [addr1,addr2,...]   new session; up to 32 addresses hashed round-robin, one kernel launch each;
//                                                      without a list the --addr address is used (legacy single mode)
//       QUIT
//     stdout: FOUND addr=0x.. nonce_dec=.. challenge=0x.. bits=N
//               multi: that address's floor becomes bits+1 and mining continues without waiting for the host
//               single: the miner pauses until the next PARAMS (original behaviour)
//             STATS hashes=.. secs=.. rate=..            every 10 s, exact: a launch never exits early, it returns its best hash
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>

typedef uint32_t u32; typedef unsigned long long u64;

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define BS0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define BS1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SS0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SS1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

#define SHA_K \
 0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u, \
 0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u, \
 0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau, \
 0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u, \
 0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u, \
 0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u, \
 0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u, \
 0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u

__device__ __constant__ u32 K[64]={SHA_K};
static const u32 HK[64]={SHA_K};

// per-job: block0 words 0..15 (words 11,12 = nonce, written by the kernel); full schedule of block1 (challenge only).
__device__ __constant__ u32 C_B0[16];
__device__ __constant__ u32 C_W1[64];

__device__ __forceinline__ void compress(u32 s[8], const u32 w[64]){
    u32 a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    #pragma unroll
    for(int i=0;i<64;i++){
        u32 t1=h+BS1(e)+CH(e,f,g)+K[i]+w[i];
        u32 t2=BS0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}

// digest for a 64-bit nonce; returns leading zero bits (s0,s1 are enough for floors <= 64).
__device__ __forceinline__ u32 digest_lz(u64 nonce, u32 *s0out, u32 *s1out){
    u32 w[64];
    #pragma unroll
    for(int i=0;i<16;i++) w[i]=C_B0[i];
    w[11]=(u32)(nonce>>32);
    w[12]=(u32)(nonce & 0xffffffffull);
    #pragma unroll
    for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
    u32 s[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    compress(s,w);
    compress(s,C_W1);
    *s0out=s[0]; *s1out=s[1];
    if(s[0]) return __clz(s[0]);
    if(s[1]) return 32u+__clz(s[1]);
    return 64u;
}

// best-of-launch: every hash with lz >= floor competes through atomicMax on (lz << 56 | offset). There is no early exit,
// so a launch always does exactly stride*iters hashes (exact accounting for STATS) and returns its best hash; the host
// reconstructs nonce = base + offset (offset < 2^56).
#define OFF_MASK 0x00FFFFFFFFFFFFFFULL
__global__ void mine_kernel(u64 base, u64 stride, u32 floor, unsigned long long *best, u64 iters){
    u64 tid = (u64)blockIdx.x*blockDim.x + threadIdx.x;
    for(u64 it=0; it<iters; it++){
        u64 off = tid + it*stride;
        u32 s0,s1; u32 lz=digest_lz(base+off,&s0,&s1);
        if(lz>=floor){ atomicMax(best, ((unsigned long long)lz<<56) | (off & OFF_MASK)); }
    }
}

// selftest: one hash for a given nonce -> digest in out[8]
__global__ void hash_one(u64 nonce, u32 *out){
    u32 w[64];
    #pragma unroll
    for(int i=0;i<16;i++) w[i]=C_B0[i];
    w[11]=(u32)(nonce>>32); w[12]=(u32)(nonce&0xffffffffull);
    #pragma unroll
    for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
    u32 s[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    compress(s,w); compress(s,C_W1);
    for(int i=0;i<8;i++) out[i]=s[i];
}

// --- host ---
static void hexToBytes(const char*h,uint8_t*out,int n){
    if(h[0]=='0'&&(h[1]=='x'||h[1]=='X')) h+=2;
    for(int i=0;i<n;i++){ unsigned b=0; sscanf(h+2*i,"%2x",&b); out[i]=(uint8_t)b; }
}
static inline u32 beword(const uint8_t*p){ return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3]; }

// block0 words from addr(20)+challenge(32): addr -> w0..w4, nonce high bytes 0, nonce in w11/w12, challenge[0..11] -> w13..w15
static void build_b0(const uint8_t addr[20], const uint8_t ch[32], u32 b0[16]){
    for(int i=0;i<5;i++) b0[i]=beword(addr+i*4);
    for(int i=5;i<=10;i++) b0[i]=0;
    b0[11]=0; b0[12]=0;
    b0[13]=beword(ch+0); b0[14]=beword(ch+4); b0[15]=beword(ch+8);
}
// block1 schedule from challenge[12..31] + padding (message length 84 bytes = 672 bits)
static void build_w1(const uint8_t ch[32], u32 w1[64]){
    u32 wb1[16];
    for(int i=0;i<5;i++) wb1[i]=beword(ch+12+i*4);
    wb1[5]=0x80000000u;
    for(int i=6;i<=14;i++) wb1[i]=0;
    wb1[15]=672u;
    for(int i=0;i<16;i++) w1[i]=wb1[i];
    for(int i=16;i<64;i++) w1[i]=SS1(w1[i-2])+w1[i-7]+SS0(w1[i-15])+w1[i-16];
}
static void build_job(const uint8_t addr[20], const uint8_t ch[32], u32 b0[16], u32 w1[64]){ build_b0(addr,ch,b0); build_w1(ch,w1); }
static void upload_job(const uint8_t addr[20], const uint8_t ch[32]){
    u32 b0[16], w1[64]; build_job(addr,ch,b0,w1);
    cudaMemcpyToSymbol(C_B0,b0,sizeof(b0));
    cudaMemcpyToSymbol(C_W1,w1,sizeof(w1));
}

// host SHA-256 of the same layout, used to ratchet per-address floors without a device round trip
static void host_compress(u32 s[8], const u32 w[64]){
    u32 a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for(int i=0;i<64;i++){
        u32 t1=h+BS1(e)+CH(e,f,g)+HK[i]+w[i];
        u32 t2=BS0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s[0]+=a;s[1]+=b;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static u32 host_lz(const u32 b0[16], const u32 w1[64], u64 nonce, u32 out[8]){
    u32 w[64];
    for(int i=0;i<16;i++) w[i]=b0[i];
    w[11]=(u32)(nonce>>32); w[12]=(u32)(nonce&0xffffffffull);
    for(int i=16;i<64;i++) w[i]=SS1(w[i-2])+w[i-7]+SS0(w[i-15])+w[i-16];
    u32 s[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    host_compress(s,w); host_compress(s,w1);
    if(out) for(int i=0;i<8;i++) out[i]=s[i];
    if(s[0]) return (u32)__builtin_clz(s[0]);
    if(s[1]) return 32u+(u32)__builtin_clz(s[1]);
    return 64u;
}
static double now_s(){ struct timeval tv; gettimeofday(&tv,0); return tv.tv_sec+tv.tv_usec/1e6; }

// non-blocking line reader on stdin (accumulates between calls). 1 = a line is ready.
static int poll_line(char*out,int maxlen){
    static int nb=0; static char lb[4096]; static int ll=0;
    if(!nb){ int f=fcntl(0,F_GETFL,0); fcntl(0,F_SETFL,f|O_NONBLOCK); nb=1; }
    char c;
    while(read(0,&c,1)==1){
        if(c=='\n'){ lb[ll]=0; strncpy(out,lb,maxlen-1); out[maxlen-1]=0; ll=0; return 1; }
        if(ll<(int)sizeof(lb)-1) lb[ll++]=c;
    }
    return 0;
}
static u64 rnd64(){ return ((u64)rand()<<48)^((u64)rand()<<32)^((u64)rand()<<16)^(u64)rand(); }

#define MAXJOBS 32
struct Job { uint8_t addr[20]; char hex[41]; u32 b0[16]; u32 floor; };
static void set_hex40(char out[41], const char*h){
    if(h[0]=='0'&&(h[1]=='x'||h[1]=='X')) h+=2;
    strncpy(out,h,40); out[40]=0;
}

int main(int argc,char**argv){
    bool selftest=false,persist=false; const char*addrHex=0,*chHex=0; u32 floor=41; int benchsecs=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--selftest")) selftest=true;
        else if(!strcmp(argv[i],"--persist")) persist=true;
        else if(!strcmp(argv[i],"--addr")&&i+1<argc) addrHex=argv[++i];
        else if(!strcmp(argv[i],"--challenge")&&i+1<argc) chHex=argv[++i];
        else if(!strcmp(argv[i],"--floor")&&i+1<argc) floor=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--benchsecs")&&i+1<argc) benchsecs=atoi(argv[++i]);
    }

    if(selftest){
        uint8_t addr[20],ch[32];
        hexToBytes("1111111111111111111111111111111111111111",addr,20);
        hexToBytes("4242424242424242424242424242424242424242424242424242424242424242",ch,32);
        upload_job(addr,ch);
        u64 nonce=((u64)1<<32)|2ULL;                   // hi=1, lo=2
        u32 *d_out; cudaMalloc(&d_out,32);
        hash_one<<<1,1>>>(nonce,d_out);
        cudaDeviceSynchronize();
        u32 s[8]; cudaMemcpy(s,d_out,32,cudaMemcpyDeviceToHost);
        char got[65]; for(int i=0;i<8;i++) sprintf(got+8*i,"%08x",s[i]); got[64]=0;
        const char*exp="51a1202b9b37848969f81d5c3bc3f1b874ad0591ef4e54b2c72c15a9fbf813ce";
        printf("digest = %s\n",got);
        bool okDev=strcmp(got,exp)==0;
        printf(okDev? "SELF-TEST: PASS\n":"SELF-TEST: FAIL (SHA-256/layout mismatch)\n");
        u32 b0[16],w1[64],hs[8]; build_job(addr,ch,b0,w1); host_lz(b0,w1,nonce,hs);
        char hgot[65]; for(int i=0;i<8;i++) sprintf(hgot+8*i,"%08x",hs[i]); hgot[64]=0;
        bool okHost=strcmp(hgot,exp)==0;
        printf(okHost? "SELF-TEST host: PASS\n":"SELF-TEST host: FAIL\n");
        return (okDev&&okHost)?0:2;
    }

    // --- persistent mode: one long connection, sessions arrive on stdin ---
    if(persist){
        uint8_t addr0[20]; bool haveAddr0=false;
        if(addrHex){ hexToBytes(addrHex,addr0,20); haveAddr0=true; }
        unsigned long long *d_found;
        if(cudaMalloc(&d_found,8)!=cudaSuccess){ fprintf(stderr,"CUDA malloc fail\n"); return 3; }
        const unsigned long long ZERO=0;
        cudaDeviceProp prop; cudaError_t perr=cudaGetDeviceProperties(&prop,0);
        int sm=prop.multiProcessorCount;
        if(perr!=cudaSuccess||sm<1||sm>512){ fprintf(stderr,"CUDA device unusable (err=%s sm=%d)\n",cudaGetErrorString(perr),sm); return 3; }
        int threads=256, blocks=sm*32; u64 stride=(u64)threads*blocks, iters=1024;
        srand((unsigned)time(0)^(unsigned)clock()^(unsigned)getpid());
        fprintf(stderr,"hb-miner persist: %s SMx%d stride=%llu launch=%.0fM hashes; waiting for PARAMS\n",prop.name,sm,(unsigned long long)stride,(double)stride*iters/1e6);
        static Job jobs[MAXJOBS]; int njobs=0; bool multi=false;
        uint8_t ch[32]; u32 w1[64];
        char line[4096], curch[70]=""; bool have=false,paused=false; u64 base=rnd64();
        u64 total=0; double t0=now_s(), lastStats=t0; int j=0;
        while(true){
            if(poll_line(line,sizeof(line))){
                if(!strncmp(line,"PARAMS",6)){
                    char cb[128]; unsigned fl=64; static char al[4096]; al[0]=0;
                    int n=sscanf(line,"PARAMS %127s %u %4095s",cb,&fl,al);
                    if(n>=2){
                        hexToBytes(cb,ch,32); build_w1(ch,w1); cudaMemcpyToSymbol(C_W1,w1,sizeof(w1));
                        const char*p=(cb[0]=='0'&&(cb[1]=='x'||cb[1]=='X'))?cb+2:cb;
                        strncpy(curch,p,64); curch[64]=0;
                        njobs=0;
                        if(n==3 && al[0]){
                            multi=true;
                            char*save=0;
                            for(char*tok=strtok_r(al,",",&save); tok && njobs<MAXJOBS; tok=strtok_r(0,",",&save)){
                                if(strlen(tok)<40) continue;
                                Job&J=jobs[njobs]; hexToBytes(tok,J.addr,20); set_hex40(J.hex,tok);
                                build_b0(J.addr,ch,J.b0); J.floor=fl; njobs++;
                            }
                        } else if(haveAddr0){
                            multi=false; Job&J=jobs[0]; memcpy(J.addr,addr0,20); set_hex40(J.hex,addrHex);
                            build_b0(J.addr,ch,J.b0); J.floor=fl; njobs=1;
                        }
                        if(njobs>0){ base=rnd64(); have=true; paused=false; j=0;
                            fprintf(stderr,"[persist] PARAMS ch=%s floor=%u jobs=%d%s\n",curch,fl,njobs,multi?" (multi)":""); }
                        else fprintf(stderr,"[persist] PARAMS carries no addresses and no --addr was given\n");
                    }
                } else if(!strncmp(line,"QUIT",4)) break;
            }
            if(!have||paused){ usleep(15000); continue; }
            Job&J=jobs[j];
            if(multi || total==0) cudaMemcpyToSymbol(C_B0,J.b0,sizeof(J.b0));
            cudaMemcpy(d_found,&ZERO,8,cudaMemcpyHostToDevice);
            mine_kernel<<<blocks,threads>>>(base,stride,J.floor,d_found,iters);
            if(cudaDeviceSynchronize()!=cudaSuccess){ fprintf(stderr,"CUDA kernel err: %s\n",cudaGetErrorString(cudaGetLastError())); return 3; }
            unsigned long long best; cudaMemcpy(&best,d_found,8,cudaMemcpyDeviceToHost);
            u64 launchBase=base;
            total+=stride*iters; base+=stride*iters;
            if(best){
                u64 nonce=launchBase+(best&OFF_MASK);
                u32 lz=host_lz(J.b0,w1,nonce,0);
                if(lz!=(u32)(best>>56)) fprintf(stderr,"[persist] lz mismatch host=%u device=%u\n",lz,(u32)(best>>56));
                printf("FOUND addr=0x%s nonce_dec=%llu challenge=0x%s bits=%u\n",J.hex,(unsigned long long)nonce,curch,lz);
                fflush(stdout);
                if(multi) J.floor=lz+1;            // keep hashing for this address only above what it already has
                else paused=true;                  // legacy: one FOUND per round, wait for the next PARAMS
            }
            j=(j+1)%njobs;
            double t=now_s();
            if(t-lastStats>=10){ lastStats=t; printf("STATS hashes=%llu secs=%.0f rate=%.3f\n",(unsigned long long)total,t-t0,total/(t-t0)/1e9); fflush(stdout); }
        }
        return 0;
    }

    if(!addrHex||!chHex){ printf("need --addr 0x<40> --challenge 0x<64> [--floor N | --benchsecs S]\n"); return 1; }
    uint8_t addr[20],ch[32]; hexToBytes(addrHex,addr,20); hexToBytes(chHex,ch,32);
    upload_job(addr,ch);

    unsigned long long *d_found;
    if(cudaMalloc(&d_found,8)!=cudaSuccess){ fprintf(stderr,"CUDA malloc fail: %s\n",cudaGetErrorString(cudaGetLastError())); return 3; }
    const unsigned long long ZERO=0;
    cudaDeviceProp prop;
    cudaError_t perr=cudaGetDeviceProperties(&prop,0);
    int sm=prop.multiProcessorCount;
    if(perr!=cudaSuccess || sm<1 || sm>512){
        fprintf(stderr,"CUDA device unusable (err=%s sm=%d)\n",cudaGetErrorString(perr),sm); return 3;
    }
    int threads=256, blocks=sm*32;
    u64 stride=(u64)threads*blocks, iters=1024;
    srand((unsigned)time(0)^(unsigned)clock());
    u64 base=rnd64();
    printf("hb-miner: addr=%s floor=%u bench=%ds | %s SMx%d threads=%d blocks=%d stride=%llu\n",
           addrHex,floor,benchsecs,prop.name,prop.multiProcessorCount,threads,blocks,(unsigned long long)stride);
    fflush(stdout);

    u64 total=0; double start=now_s(); u32 eff=benchsecs?64u:floor;  // bench: floor 64 is unreachable
    while(true){
        cudaMemcpy(d_found,&ZERO,8,cudaMemcpyHostToDevice);
        mine_kernel<<<blocks,threads>>>(base,stride,eff,d_found,iters);
        if(cudaDeviceSynchronize()!=cudaSuccess){ fprintf(stderr,"CUDA kernel err: %s\n",cudaGetErrorString(cudaGetLastError())); return 3; }
        unsigned long long best; cudaMemcpy(&best,d_found,8,cudaMemcpyDeviceToHost);
        u64 found=best?base+(best&OFF_MASK):0;
        total += stride*iters; base += stride*iters;
        double el=now_s()-start; if(el<0.001) el=0.001;
        double hr=total/el/1e9;
        if(best && !benchsecs){
            uint8_t nb[32]; memset(nb,0,32);
            for(int b=0;b<8;b++) nb[31-b]=(found>>(8*b))&0xff;   // uint256 BE, low 8 bytes
            printf("\nFOUND nonce_dec=%llu nonce_hex=0x",(unsigned long long)found);
            for(int i=0;i<32;i++) printf("%02x",nb[i]);
            printf(" challenge=0x%s\n",chHex[0]=='0'&&chHex[1]=='x'?chHex+2:chHex);
            fflush(stdout); return 0;
        }
        printf("\r[%.0fs] hashes=%.2fG rate=%.2f GH/s base=%llu      ",el,total/1e9,hr,(unsigned long long)base); fflush(stdout);
        if(benchsecs && el>=benchsecs){ printf("\nBENCH rate=%.3f GH/s (%.2fG hashes / %.0fs)\n",hr,total/1e9,el); return 0; }
    }
}

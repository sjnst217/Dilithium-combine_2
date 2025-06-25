#ifndef PQCLEAN_DILITHIUM2_CLEAN_PARAMS_H
#define PQCLEAN_DILITHIUM2_CLEAN_PARAMS_H


#define SEEDBYTES 32            // 256bit 짜리 random 값을 구할 때 이용 & A, s1, s2, DILITHIUM_K 의 seed를 생성하는 seed, 
#define CRHBYTES 64             // 512bit 짜리 random 값을 구할 때 이용 (mu, y행렬 seed 값, s1, s2)
#define DILITHIUM_N 256         // 다항식의 최대 차수
#define Q 8380417               // modulo Q
#define D 13                    // t = t1*2^D+t0 를 구할 때 사용하는 즉, t의 high bit를 구하기 위한 값
#define ROOT_OF_UNITY 1753      // NTT에서 이용하는 Dilithium의 root of unity

#define DILITHIUM_K 4           // 공개행렬 A에서 행의 크기
#define DILITHIUM_L 4           // 공개행렬 A에서 열의 크기
#define ETA 2                   // s1, s2의 범위
#define TAU 39                  // c 벡터에서 계수의 크기가 +1, -1인 계수의 개수
#define BETA 78                 // eta * tau
#define GAMMA1 (1 << 17)        // y 행렬의 계수의 범위
#define GAMMA2 ((Q-1)/88)       // t를 제외한 high bit를 구하기 위한 범위 (보통 2*gamma를 이용)        
#define OMEGA 80                // hint vector h에서의 최대 1의 개수 -> 하나의 다항식에서의 최대 1의 개수가 아니라는 점을 조심
                                // 이 omega의 제약은 BitPack, BitUnpack에서 더 효율적으로 인코딩 및 디코딩을 할 수 있도록 함

#define MONT (-4186625) // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32


#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_ALGNAME "Dilithium2"

/*

packing은 아래의 일반적인 규칙을 따르게 됨
- 1. 만약 원소 x가 포함되는 범위가 음수가 없는 정수라면 그대로 encoding
- 2. x가 [-a, b]의 범위에 존재한다면, b-x로 encoding

w1
t1
t0
s1,s2
z
와 같은 벡터들을 packing 함

각 계수들은 Dilithium의 보안레벨에 따라 달라지기 때문에 packing 할 때의 크기 역시 보안 레벨에 따라 달라지게 됨
*/


#define POLY_UNIFORM_NBLOCKS ((768 + STREAM128_BLOCKBYTES - 1)/STREAM128_BLOCKBYTES)                            // Dilithium의 계수는 23bit 표현이기 때문에, (256 * 24 / 8 +  168 - 1) / 168 = 5
#define POLY_UNIFORM_ETA_NBLOCKS ((136 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)                        // eta의 범위는 -2 ~ 2이기 때문에, 하나의 계수를 4bit 표현으로 나타낼 수 있는데, 256 * 4/8 = 128byte이다, 이는  shake함수의 하나의 block 크기도 되지 않기 때문에, 128 대신 136으로 사용
#define POLY_UNIFORM_GAMMA1_NBLOCKS ((POLYZ_PACKEDBYTES + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)       // Gamma1의 범위는 ( -2^17, 2^17] 으로 하나의 계수를 18bit 표현으로 나타낼 수 있음 256 * 18/8 = 576byte -> (576 + 136 - 1) / 136 = 5


 
#define POLYT1_PACKEDBYTES  320                 // t1           10bit 표현의 계수 256개로 이루어져 있음. 256 * 10/8 byte
#define POLYT0_PACKEDBYTES  416                 // t0           13bit 표현의 계수 256개로 이루어져 있음. 256 * 13/8 byte

#define POLYZ_PACKEDBYTES   576                 // z            18bit 표현의 계수 256개로 이루어져 있음. 256 * 18/8 byte

#define POLYW1_PACKEDBYTES  192                 // w1           6bit 표현의 계수 256개로 이루어져 있음. 256 * 6/8 byte

#define POLYETA_PACKEDBYTES  96                 // s1, s2       3bit 표현의 계수 256개로 이루어져 있음. 256 * 3/8 byte 

#define POLYVECH_PACKEDBYTES (OMEGA + DILITHIUM_K)        // h            hint vector h는 계수가 1 또는 0이기 때문에 일반적인 encoding과 다를 수 있음. 
                                                //              앞의 omega byte는 1인 항의 위치, 마지막 k byte는 각 다항식에서 1인 항이 몇개인지를 담아서 표현





// packing했을 때의 public key의 크기   (A행렬 seed, t1)
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES (SEEDBYTES + DILITHIUM_K*POLYT1_PACKEDBYTES)

// packing했을 때의 secret key의 크기   (A행렬 seed, y행렬 seed, message 해시값 seed + s1 + s2 + t0) 
#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES (3*SEEDBYTES \
        + DILITHIUM_L*POLYETA_PACKEDBYTES \
        + DILITHIUM_K*POLYETA_PACKEDBYTES \
        + DILITHIUM_K*POLYT0_PACKEDBYTES)



#define PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES (SEEDBYTES + DILITHIUM_L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)  // packing 했을 때의 signature의 크기:  challenge 벡터를 생성하는 seed + z의 다항식 벡터 + h의 다항식 벡터

typedef struct {
        int32_t coeffs[DILITHIUM_N];
} poly;
    
    
typedef struct {
        poly vec[DILITHIUM_L];
        } polyvecl;

typedef struct {
        poly vec[DILITHIUM_K];
} polyveck;  






#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "params.h"
#include "symmetric.h"
#include "fips202.h"

#define MLEN 59

#include <windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */

static int randombytes_win32_randombytes(void *buf, const size_t n)
{
    HCRYPTPROV ctx;
    BOOL tmp;

    tmp = CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptGenRandom(ctx, (unsigned long)n, (BYTE *)buf);
    if (tmp == FALSE)
    {
        return -1;
    }

    tmp = CryptReleaseContext(ctx, 0);
    if (tmp == FALSE)
    {
        return -1;
    }

    return 0;
}

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

#define DBENCH_START() // 아무 의미 없는 코드임
#define DBENCH_STOP(t)

static const int32_t zetas[DILITHIUM_N] = {
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468,
    1826347, 2353451, -359251, -2091905, 3119733, -2884855, 3111497, 2680103,
    2725464, 1024112, -1079900, 3585928, -549488, -1119584, 2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497, 280005,
    2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439,
    -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
    -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451, 3475950, 2176455, -1585221,
    -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047,
    -671102, -1228525, -22981, -1308169, -381987, 1349076, 1852771, -1430430,
    -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516, 3958618,
    -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330,
    1285669, -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961,
    2091667, 3407706, 2316500, 3817976, -3342478, 2244091, -2446433, -3562462,
    266997, 2434439, -1235728, 3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098, 909542, 819034, 495491, -1613174, -43260, -522500,
    -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
    342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353, 1595974,
    -3767016, 1250494, 2635921, -3548272, -2994039, 1869119, 1903435, -1050970,
    -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115, -1962642,
    -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993,
    -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
    -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735, 472078,
    -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687,
    -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154, 1976782};

/*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into uint64_t in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
static uint64_t load64(const uint8_t *x)
{
    uint64_t r = 0;
    for (size_t i = 0; i < 8; ++i)
    {
        r |= (uint64_t)x[i] << 8 * i;
    }

    return r;
}

/*************************************************
 * Name:        store64
 *
 * Description: Store a 64-bit integer to a byte array in little-endian order
 *
 * Arguments:   - uint8_t *x: pointer to the output byte array
 *              - uint64_t u: input 64-bit unsigned integer
 **************************************************/
static void store64(uint8_t *x, uint64_t u)
{
    for (size_t i = 0; i < 8; ++i)
    {
        x[i] = (uint8_t)(u >> 8 * i);
    }
}
/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL};

/*************************************************
 * Name:        KeccakF1600_StatePermute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - uint64_t *state: pointer to input/output Keccak state
 **************************************************/
static void KeccakF1600_StatePermute(uint64_t *state)
{
    int round;

    uint64_t Aba, Abe, Abi, Abo, Abu;
    uint64_t Aga, Age, Agi, Ago, Agu;
    uint64_t Aka, Ake, Aki, Ako, Aku;
    uint64_t Ama, Ame, Ami, Amo, Amu;
    uint64_t Asa, Ase, Asi, Aso, Asu;
    uint64_t BCa, BCe, BCi, BCo, BCu;
    uint64_t Da, De, Di, Do, Du;
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    // copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for (round = 0; round < NROUNDS; round += 2)
    {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        // thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = ROL(Age, 44);
        Aki ^= Di;
        BCi = ROL(Aki, 43);
        Amo ^= Do;
        BCo = ROL(Amo, 21);
        Asu ^= Du;
        BCu = ROL(Asu, 14);
        Eba = BCa ^ ((~BCe) & BCi);
        Eba ^= KeccakF_RoundConstants[round];
        Ebe = BCe ^ ((~BCi) & BCo);
        Ebi = BCi ^ ((~BCo) & BCu);
        Ebo = BCo ^ ((~BCu) & BCa);
        Ebu = BCu ^ ((~BCa) & BCe);

        Abo ^= Do;
        BCa = ROL(Abo, 28);
        Agu ^= Du;
        BCe = ROL(Agu, 20);
        Aka ^= Da;
        BCi = ROL(Aka, 3);
        Ame ^= De;
        BCo = ROL(Ame, 45);
        Asi ^= Di;
        BCu = ROL(Asi, 61);
        Ega = BCa ^ ((~BCe) & BCi);
        Ege = BCe ^ ((~BCi) & BCo);
        Egi = BCi ^ ((~BCo) & BCu);
        Ego = BCo ^ ((~BCu) & BCa);
        Egu = BCu ^ ((~BCa) & BCe);

        Abe ^= De;
        BCa = ROL(Abe, 1);
        Agi ^= Di;
        BCe = ROL(Agi, 6);
        Ako ^= Do;
        BCi = ROL(Ako, 25);
        Amu ^= Du;
        BCo = ROL(Amu, 8);
        Asa ^= Da;
        BCu = ROL(Asa, 18);
        Eka = BCa ^ ((~BCe) & BCi);
        Eke = BCe ^ ((~BCi) & BCo);
        Eki = BCi ^ ((~BCo) & BCu);
        Eko = BCo ^ ((~BCu) & BCa);
        Eku = BCu ^ ((~BCa) & BCe);

        Abu ^= Du;
        BCa = ROL(Abu, 27);
        Aga ^= Da;
        BCe = ROL(Aga, 36);
        Ake ^= De;
        BCi = ROL(Ake, 10);
        Ami ^= Di;
        BCo = ROL(Ami, 15);
        Aso ^= Do;
        BCu = ROL(Aso, 56);
        Ema = BCa ^ ((~BCe) & BCi);
        Eme = BCe ^ ((~BCi) & BCo);
        Emi = BCi ^ ((~BCo) & BCu);
        Emo = BCo ^ ((~BCu) & BCa);
        Emu = BCu ^ ((~BCa) & BCe);

        Abi ^= Di;
        BCa = ROL(Abi, 62);
        Ago ^= Do;
        BCe = ROL(Ago, 55);
        Aku ^= Du;
        BCi = ROL(Aku, 39);
        Ama ^= Da;
        BCo = ROL(Ama, 41);
        Ase ^= De;
        BCu = ROL(Ase, 2);
        Esa = BCa ^ ((~BCe) & BCi);
        Ese = BCe ^ ((~BCi) & BCo);
        Esi = BCi ^ ((~BCo) & BCu);
        Eso = BCo ^ ((~BCu) & BCa);
        Esu = BCu ^ ((~BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ ROL(BCe, 1);
        De = BCa ^ ROL(BCi, 1);
        Di = BCe ^ ROL(BCo, 1);
        Do = BCi ^ ROL(BCu, 1);
        Du = BCo ^ ROL(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = ROL(Ege, 44);
        Eki ^= Di;
        BCi = ROL(Eki, 43);
        Emo ^= Do;
        BCo = ROL(Emo, 21);
        Esu ^= Du;
        BCu = ROL(Esu, 14);
        Aba = BCa ^ ((~BCe) & BCi);
        Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((~BCi) & BCo);
        Abi = BCi ^ ((~BCo) & BCu);
        Abo = BCo ^ ((~BCu) & BCa);
        Abu = BCu ^ ((~BCa) & BCe);

        Ebo ^= Do;
        BCa = ROL(Ebo, 28);
        Egu ^= Du;
        BCe = ROL(Egu, 20);
        Eka ^= Da;
        BCi = ROL(Eka, 3);
        Eme ^= De;
        BCo = ROL(Eme, 45);
        Esi ^= Di;
        BCu = ROL(Esi, 61);
        Aga = BCa ^ ((~BCe) & BCi);
        Age = BCe ^ ((~BCi) & BCo);
        Agi = BCi ^ ((~BCo) & BCu);
        Ago = BCo ^ ((~BCu) & BCa);
        Agu = BCu ^ ((~BCa) & BCe);

        Ebe ^= De;
        BCa = ROL(Ebe, 1);
        Egi ^= Di;
        BCe = ROL(Egi, 6);
        Eko ^= Do;
        BCi = ROL(Eko, 25);
        Emu ^= Du;
        BCo = ROL(Emu, 8);
        Esa ^= Da;
        BCu = ROL(Esa, 18);
        Aka = BCa ^ ((~BCe) & BCi);
        Ake = BCe ^ ((~BCi) & BCo);
        Aki = BCi ^ ((~BCo) & BCu);
        Ako = BCo ^ ((~BCu) & BCa);
        Aku = BCu ^ ((~BCa) & BCe);

        Ebu ^= Du;
        BCa = ROL(Ebu, 27);
        Ega ^= Da;
        BCe = ROL(Ega, 36);
        Eke ^= De;
        BCi = ROL(Eke, 10);
        Emi ^= Di;
        BCo = ROL(Emi, 15);
        Eso ^= Do;
        BCu = ROL(Eso, 56);
        Ama = BCa ^ ((~BCe) & BCi);
        Ame = BCe ^ ((~BCi) & BCo);
        Ami = BCi ^ ((~BCo) & BCu);
        Amo = BCo ^ ((~BCu) & BCa);
        Amu = BCu ^ ((~BCa) & BCe);

        Ebi ^= Di;
        BCa = ROL(Ebi, 62);
        Ego ^= Do;
        BCe = ROL(Ego, 55);
        Eku ^= Du;
        BCi = ROL(Eku, 39);
        Ema ^= Da;
        BCo = ROL(Ema, 41);
        Ese ^= De;
        BCu = ROL(Ese, 2);
        Asa = BCa ^ ((~BCe) & BCi);
        Ase = BCe ^ ((~BCi) & BCo);
        Asi = BCi ^ ((~BCo) & BCu);
        Aso = BCo ^ ((~BCu) & BCa);
        Asu = BCu ^ ((~BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_absorb(uint64_t *s, uint32_t r, const uint8_t *m, size_t mlen, uint8_t p)
{
    size_t i;
    uint8_t t[200];

    /* Zero state */
    for (i = 0; i < 25; ++i)
    {
        s[i] = 0;
    }

    while (mlen >= r)
    {
        for (i = 0; i < r / 8; ++i)
        {
            s[i] ^= load64(m + 8 * i);
        }

        KeccakF1600_StatePermute(s);
        mlen -= r;
        m += r;
    }

    for (i = 0; i < r; ++i)
    {
        t[i] = 0;
    }
    for (i = 0; i < mlen; ++i)
    {
        t[i] = m[i];
    }
    t[i] = p;
    t[r - 1] |= 128;
    for (i = 0; i < r / 8; ++i)
    {
        s[i] ^= load64(t + 8 * i);
    }
}

/*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *h: pointer to output blocks
 *              - size_t nblocks: number of blocks to be
 *                                                squeezed (written to h)
 *              - uint64_t *s: pointer to input/output Keccak state
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_squeezeblocks(uint8_t *h, size_t nblocks, uint64_t *s, uint32_t r)
{
    while (nblocks > 0)
    {
        KeccakF1600_StatePermute(s);
        for (size_t i = 0; i < (r >> 3); i++)
        {
            store64(h + 8 * i, s[i]);
        }
        h += r;
        nblocks--;
    }
}

/*************************************************
 * Name:        keccak_inc_init
 *
 * Description: Initializes the incremental Keccak state to zero.
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 **************************************************/
static void keccak_inc_init(uint64_t *s_inc)
{
    size_t i;

    for (i = 0; i < 25; ++i)
    {
        s_inc[i] = 0;
    }
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_absorb
 *
 * Description: Incremental keccak absorb
 *              Preceded by keccak_inc_init, succeeded by keccak_inc_finalize
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 **************************************************/
static void keccak_inc_absorb(uint64_t *s_inc, uint32_t r, const uint8_t *m, size_t mlen)
{
    size_t i;

    /* Recall that s_inc[25] is the non-absorbed bytes xored into the state */
    while (mlen + s_inc[25] >= r)
    {
        for (i = 0; i < r - (uint32_t)s_inc[25]; i++)
        {
            /* Take the i'th byte from message
               xor with the s_inc[25] + i'th byte of the state; little-endian */
            s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
        }
        mlen -= (size_t)(r - s_inc[25]);
        m += r - s_inc[25];
        s_inc[25] = 0;

        KeccakF1600_StatePermute(s_inc);
    }

    for (i = 0; i < mlen; i++)
    {
        s_inc[(s_inc[25] + i) >> 3] ^= (uint64_t)m[i] << (8 * ((s_inc[25] + i) & 0x07));
    }
    s_inc[25] += mlen;
}

/*************************************************
 * Name:        keccak_inc_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
static void keccak_inc_finalize(uint64_t *s_inc, uint32_t r, uint8_t p)
{
    /* After keccak_inc_absorb, we are guaranteed that s_inc[25] < r,
       so we can always use one more byte for p in the current state. */
    s_inc[s_inc[25] >> 3] ^= (uint64_t)p << (8 * (s_inc[25] & 0x07));
    s_inc[(r - 1) >> 3] ^= (uint64_t)128 << (8 * ((r - 1) & 0x07));
    s_inc[25] = 0;
}

/*************************************************
 * Name:        keccak_inc_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - uint8_t *h: pointer to output bytes
 *              - size_t outlen: number of bytes to be squeezed
 *              - uint64_t *s_inc: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
static void keccak_inc_squeeze(uint8_t *h, size_t outlen, uint64_t *s_inc, uint32_t r)
{
    size_t i;

    /* First consume any bytes we still have sitting around */
    for (i = 0; i < outlen && i < s_inc[25]; i++)
    {
        /* There are s_inc[25] bytes left, so r - s_inc[25] is the first
           available byte. We consume from there, i.e., up to r. */
        h[i] = (uint8_t)(s_inc[(r - s_inc[25] + i) >> 3] >> (8 * ((r - s_inc[25] + i) & 0x07)));
    }
    h += i;
    outlen -= i;
    s_inc[25] -= i;

    /* Then squeeze the remaining necessary blocks */
    while (outlen > 0)
    {
        KeccakF1600_StatePermute(s_inc);

        for (i = 0; i < outlen && i < r; i++)
        {
            h[i] = (uint8_t)(s_inc[i >> 3] >> (8 * (i & 0x07)));
        }
        h += i;
        outlen -= i;
        s_inc[25] = r - i;
    }
}

void shake128_inc_init(shake128incctx *state)
{
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen)
{
    keccak_inc_absorb(state->ctx, SHAKE128_RATE, input, inlen);
}

void shake128_inc_finalize(shake128incctx *state)
{
    keccak_inc_finalize(state->ctx, SHAKE128_RATE, 0x1F);
}

void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state)
{
    keccak_inc_squeeze(output, outlen, state->ctx, SHAKE128_RATE);
}

void shake128_inc_ctx_clone(shake128incctx *dest, const shake128incctx *src)
{
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void shake128_inc_ctx_release(shake128incctx *state)
{
    free(state->ctx);
}

void shake256_inc_init(shake256incctx *state)
{
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen)
{
    keccak_inc_absorb(state->ctx, SHAKE256_RATE, input, inlen);
}

void shake256_inc_finalize(shake256incctx *state)
{
    keccak_inc_finalize(state->ctx, SHAKE256_RATE, 0x1F);
}

void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state)
{
    keccak_inc_squeeze(output, outlen, state->ctx, SHAKE256_RATE);
}

void shake256_inc_ctx_clone(shake256incctx *dest, const shake256incctx *src)
{
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void shake256_inc_ctx_release(shake256incctx *state)
{
    free(state->ctx);
}

/*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - const uint8_t *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen)
{
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE128_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                            (written to output)
 *              - shake128ctx *state: pointer to input/output Keccak state
 **************************************************/
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state)
{
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE128_RATE);
}

void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src)
{
    dest->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKECTX_BYTES);
}

/** Release the allocated state. Call only once. */
void shake128_ctx_release(shake128ctx *state)
{
    free(state->ctx);
}

/*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - shake256ctx *state: pointer to (uninitialized) output Keccak state
 *              - const uint8_t *input: pointer to input to be absorbed
 *                                            into s
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen)
{
    state->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_absorb(state->ctx, SHAKE256_RATE, input, inlen, 0x1F);
}

/*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *output: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed
 *                                (written to output)
 *              - shake256ctx *state: pointer to input/output Keccak state
 **************************************************/
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state)
{
    keccak_squeezeblocks(output, nblocks, state->ctx, SHAKE256_RATE);
}

void shake256_ctx_clone(shake256ctx *dest, const shake256ctx *src)
{
    dest->ctx = malloc(PQC_SHAKECTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKECTX_BYTES);
}

/** Release the allocated state. Call only once. */
void shake256_ctx_release(shake256ctx *state)
{
    free(state->ctx);
}

/*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *output: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    size_t nblocks = outlen / SHAKE128_RATE;
    uint8_t t[SHAKE128_RATE];
    shake128ctx s;

    shake128_absorb(&s, input, inlen);
    shake128_squeezeblocks(output, nblocks, &s);

    output += nblocks * SHAKE128_RATE;
    outlen -= nblocks * SHAKE128_RATE;

    if (outlen)
    {
        shake128_squeezeblocks(t, 1, &s);
        for (size_t i = 0; i < outlen; ++i)
        {
            output[i] = t[i];
        }
    }
    shake128_ctx_release(&s);
}

/*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *output: pointer to output
 *              - size_t outlen: requested output length in bytes
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen: length of input in bytes
 **************************************************/
void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
    size_t nblocks = outlen / SHAKE256_RATE;
    uint8_t t[SHAKE256_RATE];
    shake256ctx s;

    shake256_absorb(&s, input, inlen);
    shake256_squeezeblocks(output, nblocks, &s);

    output += nblocks * SHAKE256_RATE;
    outlen -= nblocks * SHAKE256_RATE;

    if (outlen)
    {
        shake256_squeezeblocks(t, 1, &s);
        for (size_t i = 0; i < outlen; ++i)
        {
            output[i] = t[i];
        }
    }
    shake256_ctx_release(&s);
}

void sha3_256_inc_init(sha3_256incctx *state)
{
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_256_inc_ctx_clone(sha3_256incctx *dest, const sha3_256incctx *src)
{
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_256_inc_ctx_release(sha3_256incctx *state)
{
    free(state->ctx);
}

void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen)
{
    keccak_inc_absorb(state->ctx, SHA3_256_RATE, input, inlen);
}

void sha3_256_inc_finalize(uint8_t *output, sha3_256incctx *state)
{
    uint8_t t[SHA3_256_RATE];
    keccak_inc_finalize(state->ctx, SHA3_256_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_256_RATE);

    sha3_256_inc_ctx_release(state);

    for (size_t i = 0; i < 32; i++)
    {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
{
    uint64_t s[25];
    uint8_t t[SHA3_256_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

    for (size_t i = 0; i < 32; i++)
    {
        output[i] = t[i];
    }
}

void sha3_384_inc_init(sha3_384incctx *state)
{
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_384_inc_ctx_clone(sha3_384incctx *dest, const sha3_384incctx *src)
{
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_384_inc_absorb(sha3_384incctx *state, const uint8_t *input, size_t inlen)
{
    keccak_inc_absorb(state->ctx, SHA3_384_RATE, input, inlen);
}

void sha3_384_inc_ctx_release(sha3_384incctx *state)
{
    free(state->ctx);
}

void sha3_384_inc_finalize(uint8_t *output, sha3_384incctx *state)
{
    uint8_t t[SHA3_384_RATE];
    keccak_inc_finalize(state->ctx, SHA3_384_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_384_RATE);

    sha3_384_inc_ctx_release(state);

    for (size_t i = 0; i < 48; i++)
    {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_384
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen)
{
    uint64_t s[25];
    uint8_t t[SHA3_384_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_384_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_384_RATE);

    for (size_t i = 0; i < 48; i++)
    {
        output[i] = t[i];
    }
}

void sha3_512_inc_init(sha3_512incctx *state)
{
    state->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (state->ctx == NULL)
    {
        exit(111);
    }
    keccak_inc_init(state->ctx);
}

void sha3_512_inc_ctx_clone(sha3_512incctx *dest, const sha3_512incctx *src)
{
    dest->ctx = malloc(PQC_SHAKEINCCTX_BYTES);
    if (dest->ctx == NULL)
    {
        exit(111);
    }
    memcpy(dest->ctx, src->ctx, PQC_SHAKEINCCTX_BYTES);
}

void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *input, size_t inlen)
{
    keccak_inc_absorb(state->ctx, SHA3_512_RATE, input, inlen);
}

void sha3_512_inc_ctx_release(sha3_512incctx *state)
{
    free(state->ctx);
}

void sha3_512_inc_finalize(uint8_t *output, sha3_512incctx *state)
{
    uint8_t t[SHA3_512_RATE];
    keccak_inc_finalize(state->ctx, SHA3_512_RATE, 0x06);

    keccak_squeezeblocks(t, 1, state->ctx, SHA3_512_RATE);

    sha3_512_inc_ctx_release(state);

    for (size_t i = 0; i < 64; i++)
    {
        output[i] = t[i];
    }
}

/*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - uint8_t *output:      pointer to output
 *              - const uint8_t *input: pointer to input
 *              - size_t inlen:   length of input in bytes
 **************************************************/
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
{
    uint64_t s[25];
    uint8_t t[SHA3_512_RATE];

    /* Absorb input */
    keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);

    /* Squeeze output */
    keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

    for (size_t i = 0; i < 64; i++)
    {
        output[i] = t[i];
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_dilithium_shake128_stream_init(shake128incctx *state, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
    uint8_t t[2];
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);

    shake128_inc_init(state);
    shake128_inc_absorb(state, seed, SEEDBYTES);
    shake128_inc_absorb(state, t, 2);
    shake128_inc_finalize(state);
}

void PQCLEAN_DILITHIUM2_CLEAN_dilithium_shake256_stream_init(shake256incctx *state, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    uint8_t t[2];
    t[0] = (uint8_t)nonce;
    t[1] = (uint8_t)(nonce >> 8);

    shake256_inc_init(state);
    shake256_inc_absorb(state, seed, CRHBYTES);
    shake256_inc_absorb(state, t, 2);
    shake256_inc_finalize(state);
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce(int64_t a)
{
    int32_t t;

    t = (int32_t)((uint64_t)a * (uint64_t)QINV);
    t = (a - (int64_t)t * Q) >> 32;
    return t;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_reduce32(int32_t a)
{
    int32_t t;

    t = (a + (1 << 22)) >> 23;
    t = a - t * Q;
    return t;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_caddq(int32_t a)
{
    a += (a >> 31) & Q; // a가 음수이면 a + Q, a가 양수이면 그대로
    return a;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_freeze(int32_t a)
{
    a = PQCLEAN_DILITHIUM2_CLEAN_reduce32(a);
    a = PQCLEAN_DILITHIUM2_CLEAN_caddq(a);
    return a;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_power2round(int32_t *a0, int32_t a)
{ // t = t1*s^d + t0 로 t1, t0를 생성하는 코드
    int32_t a1;

    a1 = (a + (1 << (D - 1)) - 1) >> D; // t1은 결국 t를 2^d로 나누었을 때의 몫이라고 볼 수 있음. 근데 여기에서, 실제로 나누었을 때의 몫이 아닌, 나머지값인 t0가 양수 또는 음수의 범위에서 2^(D-1)보다 작아야 한다.
                                        // 그렇기 때문에, a + (1 << (D - 1)) - 1 를 해 주는 것으로 t0가 양수 또는 음수의 범위에서 2^(D-1) 보다 작아짐
    *a0 = a - (a1 << D);                // 이후 t0 = t - t * 2^D 로 t0를 설정
    return a1;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_decompose(int32_t *a0, int32_t a)  // w0, w
{
    int32_t a1;
    //printf("test\n");
    a1 = (a + 127) >> 7;                        // a1 = (w + 127) >> 7                          w는 23bit 표현으로 그러한 w를 128로 나누었을때의 몫의 올림값을 a1이라고 한다.       
                                                //                                              0 : 0 , 1 ~ 128 : 1 * 11275, 129 ~ 256 : 2 * 11275 ... , 5377 ~ 5504 : 43 * 11275, ... , 8380289 ~ 8380416 : 65472 * 11275 
                                                //                                              [      ,     0, 744  ] : 0, [   745,  1488, 2232 ] : 1, ... , [ 63241, 63984, 64728] : 43, [ 64729, 65472,		 ] : 44         -> 여기에 있는 숫자는 모두 >> 7을 한 숫자를 기준으로 함
    a1 = (a1 * 11275 + (1 << 23)) >> 24;        // a1 = (a1 * 11275 + (1 << 23)) >> 24          그러한 a1을 a1 * 11275 + (1 << 23) >> 24 하는 것으로 설명과 문서와 같은 방식으로 작동하게 됨
                                                //                                              이러한 방식은 Q가 2^24에 가깝고, 그렇다면 w0 는 2^23과 비슷하기 때문에 위와 같이 계산을 하도록 할 수 있음
    a1 ^= ((43 - a1) >> 31) & a1;               // a1 = a1 ^ ((43 - a1) >> 31) & a1             이 때 a1의 값이 44일 경우 0으로 변경 해 주는것으로 high bit의 carry가 진행되지 않도록 해 준다.

    *a0 = a - a1 * 2 * GAMMA2;                  // a0 = w - a1 * 2 * GAMMA2                     여기에서 w0를 구하기 위해서 w - w1 * 2 * GAMMA2를 진행해주고
    //*a0 -= (((Q - 1) / 2 - *a0) >> 31) & Q;     // a0 = a0 - (((Q - 1) / 2 - a0) >> 31) & Q     
    return a1;                                  // 
}

unsigned int PQCLEAN_DILITHIUM2_CLEAN_make_hint(int32_t a0, int32_t a1)
{
    if (a0 > GAMMA2 || a0 < -GAMMA2 || (a0 == -GAMMA2 && a1 != 0))
    {
        return 1;
    }

    return 0;
}

int32_t PQCLEAN_DILITHIUM2_CLEAN_use_hint(int32_t a, unsigned int hint)
{
    int32_t a0, a1;

    a1 = PQCLEAN_DILITHIUM2_CLEAN_decompose(&a0, a);
    if (hint == 0)
    {
        return a1;
    }

    if (a0 > 0)
    {
        if (a1 == 43)
        {
            return 0;
        }
        return a1 + 1;
    }
    if (a1 == 0)
    {
        return 43;
    }
    return a1 - 1;
}

// 3bit 8개 -> 8bit 3개
void PQCLEAN_DILITHIUM2_CLEAN_polyeta_pack(uint8_t *r, const poly *a)
{
    unsigned int i;
    uint8_t t[8];
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (uint8_t)(ETA - a->coeffs[8 * i + 0]);   // 한번에 8개의 계수를 가져와서 2 - coef (범위 : 0 ~ 4)로 변경하여 pack 진행을 위해
        t[1] = (uint8_t)(ETA - a->coeffs[8 * i + 1]);   // t[i] = 2 - coef 를 진행
        t[2] = (uint8_t)(ETA - a->coeffs[8 * i + 2]);
        t[3] = (uint8_t)(ETA - a->coeffs[8 * i + 3]);
        t[4] = (uint8_t)(ETA - a->coeffs[8 * i + 4]);
        t[5] = (uint8_t)(ETA - a->coeffs[8 * i + 5]);
        t[6] = (uint8_t)(ETA - a->coeffs[8 * i + 6]);
        t[7] = (uint8_t)(ETA - a->coeffs[8 * i + 7]);   // 이는 3bit로 표현할 수 있기 때문에,        

        r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);                 // r[0] =   t[2]의 하위 2bit | t[1] | t[0]
        r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);   // r[1] =   t[5]의 하위 1bit | t[4] | t[3] | t[2]의 상위 1bit
        r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);                 // r[2] =   t[7]             | t[6] | t[5] 의 상위 2bit
    }

    DBENCH_STOP(*tpack);
}

// 8bit 3개 -> 3bit 8개
void PQCLEAN_DILITHIUM2_CLEAN_polyeta_unpack(poly *r, const uint8_t *a)
{   
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 8; ++i)
    {   // & 0x7 -> & 0111 즉 하위 3bit를 남긴다는 의미임
        r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;     // 각 계수를 3bit씩 쪼개서 각 계수에 집어 넣어줌
        r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
        r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
        r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
        r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
        r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
        r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
        r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

        r->coeffs[8 * i + 0] = ETA - r->coeffs[8 * i + 0];  // 기존 범위 : -2 ~ 2 -> 0 ~ 4 로 encode 를 진행했었기 때문에
        r->coeffs[8 * i + 1] = ETA - r->coeffs[8 * i + 1];  // 기존의 범위로 돌아가기 위해 다시 0 ~ 4 -> -2 ~ 2 로 decode 진행
        r->coeffs[8 * i + 2] = ETA - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = ETA - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = ETA - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = ETA - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = ETA - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = ETA - r->coeffs[8 * i + 7];
    }

    DBENCH_STOP(*tpack);
}

void PQCLEAN_DILITHIUM2_CLEAN_polyt1_pack(uint8_t *r, const poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 4; ++i)                                                       // 10bit 4개를 8bit 5개로 encode 해주는 코드임
    {
        r[5 * i + 0] = (uint8_t)(a->coeffs[4 * i + 0] >> 0);                                    // coef[0]의 하위 8bit
        r[5 * i + 1] = (uint8_t)((a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2));    // coef[1]의 하위 6bit | coef[0]의 상위 2bit
        r[5 * i + 2] = (uint8_t)((a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4));    // coef[2]의 하위 4bit | coef[1]의 상위 4bit
        r[5 * i + 3] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6));    // coef[3]의 하위 2bit | coef[2]의 상위 6bit
        r[5 * i + 4] = (uint8_t)(a->coeffs[4 * i + 3] >> 2);                                    // coef[3]의 상위 8bit
    }

    DBENCH_STOP(*tpack);
}

void PQCLEAN_DILITHIUM2_CLEAN_polyt1_unpack(poly *r, const uint8_t *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
        r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
        r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
        r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
    }

    DBENCH_STOP(*tpack);
}

// 13bit 8개 -> 8bit 13개
void PQCLEAN_DILITHIUM2_CLEAN_polyt0_pack(uint8_t *r, const poly *a)
{
    unsigned int i;
    uint32_t t[8];
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 8; ++i)
    {
        t[0] = (1 << (D - 1)) - a->coeffs[8 * i + 0];   // t0는 범위가 ( -2^(D - 1), 2^(D - 1) ]이기 때문에, 2^(D - 1) - t0 를 통해 0 ~ 2^D-1의 범위로 나타낼 수 있다.
        t[1] = (1 << (D - 1)) - a->coeffs[8 * i + 1];   
        t[2] = (1 << (D - 1)) - a->coeffs[8 * i + 2];
        t[3] = (1 << (D - 1)) - a->coeffs[8 * i + 3];
        t[4] = (1 << (D - 1)) - a->coeffs[8 * i + 4];
        t[5] = (1 << (D - 1)) - a->coeffs[8 * i + 5];
        t[6] = (1 << (D - 1)) - a->coeffs[8 * i + 6];
        t[7] = (1 << (D - 1)) - a->coeffs[8 * i + 7];   // 이를 위해 t[i] = (1 << (D - 1)) - t0로 encode를 진행 (13bit 표현)

        r[13 * i + 0] = (uint8_t)t[0];                  // t[0]의 하위 8bit
        
        r[13 * i + 1] = (uint8_t)(t[0] >> 8);           
        r[13 * i + 1] |= (uint8_t)(t[1] << 5);          // t[1]의 하위 3bit | t[0]의 상위 5bit
        
        r[13 * i + 2] = (uint8_t)(t[1] >> 3);           // t[1]의 중간 8bit
       
        r[13 * i + 3] = (uint8_t)(t[1] >> 11);          
        r[13 * i + 3] |= (uint8_t)(t[2] << 2);          // t[2]의 하위 6bit | t[1]의 상위 2bit
        
        r[13 * i + 4] = (uint8_t)(t[2] >> 6);           
        r[13 * i + 4] |= (uint8_t)(t[3] << 7);          // t[3]의 하위 1bit | t[2]의 상위 7bit
        
        r[13 * i + 5] = (uint8_t)(t[3] >> 1);           // t[3]의 중위 8bit
        
        r[13 * i + 6] = (uint8_t)(t[3] >> 9);           
        r[13 * i + 6] |= (uint8_t)(t[4] << 4);          // t[4]의 하위 4bit | t[3]의 상위 4bit
        
        r[13 * i + 7] = (uint8_t)(t[4] >> 4);           // t[4]의 중위 8bit
        
        r[13 * i + 8] = (uint8_t)(t[4] >> 12);          
        r[13 * i + 8] |= (uint8_t)(t[5] << 1);          // t[5]의 하위 7bit | t[4]의 상위 1bit
        
        r[13 * i + 9] = (uint8_t)(t[5] >> 7);           
        r[13 * i + 9] |= (uint8_t)(t[6] << 6);          // t[6]의 하위 2bit | t[5]의 상위 6bit
        
        r[13 * i + 10] = (uint8_t)(t[6] >> 2);          // t[6]의 중위 8bit
        
        r[13 * i + 11] = (uint8_t)(t[6] >> 10);         
        r[13 * i + 11] |= (uint8_t)(t[7] << 3);         // t[7]의 하위 5bit | t[6]의 상위 3bit
        
        r[13 * i + 12] = (uint8_t)(t[7] >> 5);          // t[7]의 상위 8bit
    }

    DBENCH_STOP(*tpack);
}

// 8bit 13개 -> 13bit 8개
void PQCLEAN_DILITHIUM2_CLEAN_polyt0_unpack(poly *r, const uint8_t *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 8; ++i)
    {   // 8bit 짜리 13개를 13bit 8개로 변경
        r->coeffs[8 * i + 0] = a[13 * i + 0];
        r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
        r->coeffs[8 * i + 0] &= 0x1FFF;         // 0b 0001 1111 1111 1111    즉, 13bit 로 마스킹

        r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
        r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
        r->coeffs[8 * i + 1] &= 0x1FFF;

        r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
        r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
        r->coeffs[8 * i + 2] &= 0x1FFF;

        r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
        r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
        r->coeffs[8 * i + 3] &= 0x1FFF;

        r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
        r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
        r->coeffs[8 * i + 4] &= 0x1FFF;

        r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
        r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
        r->coeffs[8 * i + 5] &= 0x1FFF;

        r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
        r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
        r->coeffs[8 * i + 6] &= 0x1FFF;

        r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
        r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
        r->coeffs[8 * i + 7] &= 0x1FFF;

        r->coeffs[8 * i + 0] = (1 << (D - 1)) - r->coeffs[8 * i + 0];   // 기존의 t0의 범위는 ( 2^(D-1), 2^(D-1) ] 였고 이를 unsigned로 변경하기 위해서 t0 = 2^(D-1) - t0로 encode를 했었기 때문에
        r->coeffs[8 * i + 1] = (1 << (D - 1)) - r->coeffs[8 * i + 1];   // 다시 기존 범위로 돌리기 위해서 t0 = 2^(D-1) - t0를 진행해 줌
        r->coeffs[8 * i + 2] = (1 << (D - 1)) - r->coeffs[8 * i + 2];
        r->coeffs[8 * i + 3] = (1 << (D - 1)) - r->coeffs[8 * i + 3];
        r->coeffs[8 * i + 4] = (1 << (D - 1)) - r->coeffs[8 * i + 4];
        r->coeffs[8 * i + 5] = (1 << (D - 1)) - r->coeffs[8 * i + 5];
        r->coeffs[8 * i + 6] = (1 << (D - 1)) - r->coeffs[8 * i + 6];
        r->coeffs[8 * i + 7] = (1 << (D - 1)) - r->coeffs[8 * i + 7];
    }

    DBENCH_STOP(*tpack);
}

void PQCLEAN_DILITHIUM2_CLEAN_polyz_pack(uint8_t *r, const poly *a)
{
    unsigned int i;
    uint32_t t[4];
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 4; ++i)
    {
        t[0] = GAMMA1 - a->coeffs[4 * i + 0];
        t[1] = GAMMA1 - a->coeffs[4 * i + 1];
        t[2] = GAMMA1 - a->coeffs[4 * i + 2];
        t[3] = GAMMA1 - a->coeffs[4 * i + 3];

        r[9 * i + 0] = (uint8_t)t[0];
        r[9 * i + 1] = (uint8_t)(t[0] >> 8);
        r[9 * i + 2] = (uint8_t)(t[0] >> 16);
        r[9 * i + 2] |= (uint8_t)(t[1] << 2);
        r[9 * i + 3] = (uint8_t)(t[1] >> 6);
        r[9 * i + 4] = (uint8_t)(t[1] >> 14);
        r[9 * i + 4] |= (uint8_t)(t[2] << 4);
        r[9 * i + 5] = (uint8_t)(t[2] >> 4);
        r[9 * i + 6] = (uint8_t)(t[2] >> 12);
        r[9 * i + 6] |= (uint8_t)(t[3] << 6);
        r[9 * i + 7] = (uint8_t)(t[3] >> 2);
        r[9 * i + 8] = (uint8_t)(t[3] >> 10);
    }

    DBENCH_STOP(*tpack);
}

//8bit 9개 -> 18bit 4개
void PQCLEAN_DILITHIUM2_CLEAN_polyz_unpack(poly *r, const uint8_t *a)
{   // y행렬에 a(SHAKE256)를 통해 rejection sampling을 진행 
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r->coeffs[4 * i + 0] = a[9 * i + 0];                    // a[0]
        r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 1] << 8;    // a[1] | a[0] 
        r->coeffs[4 * i + 0] |= (uint32_t)a[9 * i + 2] << 16;   // a[2] | a[1] | a[0]
        r->coeffs[4 * i + 0] &= 0x3FFFF;                        // 0011 11111111 11111111   (18bit masking) 

        r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;               // a[2] 상위 6bit
        r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 3] << 6;    // a[3] | a[2] 상위 6bit
        r->coeffs[4 * i + 1] |= (uint32_t)a[9 * i + 4] << 14;   // a[4] | a[3] | a[2] 상위 6bit
        r->coeffs[4 * i + 1] &= 0x3FFFF;                        // 1111 11111111 111111     (18bit masking)

        r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;               // a[4] 상위 4bit
        r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 5] << 4;    // a[5] | a[4] 상위 4bit
        r->coeffs[4 * i + 2] |= (uint32_t)a[9 * i + 6] << 12;   // a[6] | a[5] | a[4] 상위 4bit
        r->coeffs[4 * i + 2] &= 0x3FFFF;                        // 111111 11111111 1111     (18bit masking)

        r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;               // a[6] 상위 2bit
        r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 7] << 2;    // a[7] | a[6] 상위 2bit
        r->coeffs[4 * i + 3] |= (uint32_t)a[9 * i + 8] << 10;   // a[6] | a[7] | a[6] 상위 2bit
        r->coeffs[4 * i + 3] &= 0x3FFFF;                        // 11111111 11111111 11     (18bit masking)

        r->coeffs[4 * i + 0] = GAMMA1 - r->coeffs[4 * i + 0];   // 위의 과정을 모두 마친 다음 범위를 ( -gamma1 + 1, gamma1 ] -> [0, 2gamma1 - 1] 로 변경해주기 위해 GAMMA1 - coef를 진행
        r->coeffs[4 * i + 1] = GAMMA1 - r->coeffs[4 * i + 1];
        r->coeffs[4 * i + 2] = GAMMA1 - r->coeffs[4 * i + 2];
        r->coeffs[4 * i + 3] = GAMMA1 - r->coeffs[4 * i + 3];
    }

    DBENCH_STOP(*tpack);
}

// 6bit 4개 -> 8bit 3개
void PQCLEAN_DILITHIUM2_CLEAN_polyw1_pack(uint8_t *r, const poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N / 4; ++i)
    {
        r[3 * i + 0] =  (uint8_t)(a->coeffs[4 * i + 0]);       
        r[3 * i + 0] |= (uint8_t)(a->coeffs[4 * i + 1] << 6);   // w1[1] 하위 2bit | w1[0] 8bit
        
        r[3 * i + 1] =  (uint8_t)(a->coeffs[4 * i + 1] >> 2);
        r[3 * i + 1] |= (uint8_t)(a->coeffs[4 * i + 2] << 4);   // w1[2] 하위 4bit | w1[1] 상위 4bit 
        
        r[3 * i + 2] =  (uint8_t)(a->coeffs[4 * i + 2] >> 4);
        r[3 * i + 2] |= (uint8_t)(a->coeffs[4 * i + 3] << 2);   // w1[3] 8bit      | w1[2] 상위 2bit 
    }

    DBENCH_STOP(*tpack);
}

void PQCLEAN_DILITHIUM2_CLEAN_ntt(int32_t a[DILITHIUM_N])
{
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1)
    {
        for (start = 0; start < DILITHIUM_N; start = j + len)
        {
            zeta = zetas[++k];
            for (j = start; j < start + len; ++j)
            {
                t = PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_invntt_tomont(int32_t a[DILITHIUM_N])
{
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978; // mont^2/256

    k = 256;
    for (len = 1; len < DILITHIUM_N; len <<= 1)
    {
        for (start = 0; start < DILITHIUM_N; start = j + len)
        {
            zeta = -zetas[--k];
            for (j = start; j < start + len; ++j)
            {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; ++j)
    {
        a[j] = PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce((int64_t)f * a[j]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_reduce(poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_reduce32(a->coeffs[i]);
    }

    DBENCH_STOP(*tred);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_caddq(poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_caddq(a->coeffs[i]);
    }

    DBENCH_STOP(*tred);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_add(poly *c, const poly *a, const poly *b)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }

    DBENCH_STOP(*tadd);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_sub(poly *c, const poly *a, const poly *b)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }

    DBENCH_STOP(*tadd);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_shiftl(poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        a->coeffs[i] <<= D;
    }

    DBENCH_STOP(*tmul);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(poly *a)
{
    DBENCH_START();

    PQCLEAN_DILITHIUM2_CLEAN_ntt(a->coeffs);

    DBENCH_STOP(*tmul);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_invntt_tomont(poly *a)
{
    DBENCH_START();

    PQCLEAN_DILITHIUM2_CLEAN_invntt_tomont(a->coeffs);

    DBENCH_STOP(*tmul);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        c->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
    }

    DBENCH_STOP(*tmul);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_power2round(poly *a1, poly *a0, const poly *a)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_power2round(&a0->coeffs[i], a->coeffs[i]);
    }

    DBENCH_STOP(*tround);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_decompose(poly *a1, poly *a0, const poly *a) // w1, w0, w
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        a1->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_decompose(&a0->coeffs[i], a->coeffs[i]);   // w1 = decompose(w0, w)
    }

    DBENCH_STOP(*tround);
}

unsigned int PQCLEAN_DILITHIUM2_CLEAN_poly_make_hint(poly *h, const poly *a0, const poly *a1)
{
    unsigned int i, s = 0;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        h->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_make_hint(a0->coeffs[i], a1->coeffs[i]);
        s += h->coeffs[i];
    }

    DBENCH_STOP(*tround);
    return s;
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_use_hint(poly *b, const poly *a, const poly *h)
{
    unsigned int i;
    DBENCH_START();

    for (i = 0; i < DILITHIUM_N; ++i)
    {
        b->coeffs[i] = PQCLEAN_DILITHIUM2_CLEAN_use_hint(a->coeffs[i], h->coeffs[i]);
    }

    DBENCH_STOP(*tround);
}

// c * s1 + y 의 계수중 GAMMA1 - BETA 보다 큰 값이 있다면 rej로 가도록 하는 함수
// w0 - c * s2의 계수중 GAMMA2 - BETA 보다 큰 값이 있다면 rej로 가도록 하는 함수
int PQCLEAN_DILITHIUM2_CLEAN_poly_chknorm(const poly *a, int32_t B) // z= c*s1+y, GAMMA1 - BETA or GAMMA2 - BETA     BETA = eta * tau 
{
    unsigned int i;
    int32_t t;
    DBENCH_START();

    if (B > (Q - 1) / 8)    // GAMMA1 - BETA > (Q - 1) / 8 -> GAMMA1의 최대 계수 : 2^17(131,072), BETA의 최대 계수 : 78 GAMMA2의 최대 계수 : Q-1/88(95,232)
    {                       // Q : 8380417, Q - 1 / 8 -> 1,047,552
        return 1;           // 즉, 어딘가에서 오류가 나서 GAMMA1 - BETA or GAMMA2 - BETA 의 크기가 이상하면 reject
    }

    /* It is ok to leak which coefficient violates the bound since
       the probability for each coefficient is independent of secret
       data but we must not leak the sign of the centralized representative. */
    for (i = 0; i < DILITHIUM_N; ++i)
    {
        /* Absolute value */
        t = a->coeffs[i] >> 31;                     // a의 계수는 음수일 수 있기 때문에, t에 현재 계수가 음수인지 아닌지 확인해주고 음수라면 t = 0x1111...1111로 1로 가득 찬 bit가 될 것이고, 아니라면 0으로 가득 찬 bit가 된다.
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);  // a의 계수가 양수였다면 그대로, 음수였다면 양수로 변경해주는 코드 (즉, 계수의 절대값을 구해줌)

        if (t >= B)                                 // 그 계수의 절대값이 bound(GAMMA1 - BETA or GAMMA2 - BETA) 보다 크거나 같다면
        {
            DBENCH_STOP(*tsample);
            return 1;                               // reject
        }
    }

    DBENCH_STOP(*tsample);
    return 0;
}

static unsigned int rej_uniform(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen)
{
    unsigned int ctr, pos;
    uint32_t t;
    DBENCH_START();

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen)
    {                                    // 3byte    즉, 24bit씩 가져와서
        t = buf[pos++];                  // t = 00000000 00000000 00000000 의 마지막 부분을 채우고   -> 00000000 00000000 buf[0]
        t |= (uint32_t)buf[pos++] << 8;  // t = 00000000 00000000 buf[0]   의 2번째 부분을 채우고    -> 00000000 buf[1] buf[0]
        t |= (uint32_t)buf[pos++] << 16; // t = 00000000 buf[1] buf[0]     의 1번째 부분을 채우고    -> buf[2] buf[1] buf[0]
        t &= 0x7FFFFF;                   // t = buf[2] buf[1] buf[0] 의 하위 23bit를 남김
        if (t < Q)
        {
            a[ctr++] = t; // 만약 그렇게 rejection sampling한 값이 Q보다 작다면,
        }
    }

    DBENCH_STOP(*tsample);
    return ctr; // 총 채운 값의 개수를 return
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_uniform(poly *a, const uint8_t seed[SEEDBYTES], uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES + 2]; // 5 * stream128 + 2
    stream128_state state;

    stream128_init(&state, seed, nonce);
    stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

    ctr = rej_uniform(a->coeffs, DILITHIUM_N, buf, buflen); // rejection sampling을 통해 a의 계수를 ctr만큼 채움

    while (ctr < DILITHIUM_N)
    { // 총 채운 값들이 256개가 되지 않는다면,
        off = buflen % 3;
        for (i = 0; i < off; ++i)
        {
            buf[i] = buf[buflen - off + i];
        }

        stream128_squeezeblocks(buf + off, 1, &state);                       // shake128로 168byte 블럭을 하나 생성
        buflen = STREAM128_BLOCKBYTES + off;                                 // buflen을 168 + off로 변경
        ctr += rej_uniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen); // 남은 애들을 채워줌
    }
    stream128_release(&state);
}

static unsigned int rej_eta(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen)
{
    unsigned int ctr, pos;
    uint32_t t0, t1;
    DBENCH_START();

    ctr = pos = 0;
    while (ctr < len && pos < buflen)
    {
        t0 = buf[pos] & 0x0F; // buf[0]의 하위 4bit를 가져와서 t0에
        t1 = buf[pos++] >> 4; // buf[0]의 상위 4bit를 가져와서 t1에

        if (t0 < 15)
        {                                   // 각 t0, t1의 값이 15가 아니면 accept이 됨
            t0 = t0 - (205 * t0 >> 10) * 5; // t0의 값이 0~4 -> 0, 5~9 -> 5, 10~14 -> 10
                                            // 0~4 -> 0 ~ 4 , 5~9 -> 0 ~ 4 , 10~14 -> 0 ~ 4     -> 이건 결국 % 5 연산을 진행하는 것과 같음 이를 빠르게 수행하기 위해 위와 같이 연산을 진행한 것임
            a[ctr++] = 2 - t0;              // 0~4 -> 2 ~ -2, 5~9 -> 2 ~ -2, 10~14 -> 2 ~ -2
        } // 이런 식으로 -2 ~ 2로 rejection sampling을 진행하게 됨
        if (t1 < 15 && ctr < len)
        {
            t1 = t1 - (205 * t1 >> 10) * 5; // 위의 코드와 동일
            a[ctr++] = 2 - t1;
        }
    }

    DBENCH_STOP(*tsample);
    return ctr;
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_eta(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    unsigned int ctr;
    unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES;
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * STREAM256_BLOCKBYTES];
    stream256_state state;

    stream256_init(&state, seed, nonce);
    stream256_squeezeblocks(buf, POLY_UNIFORM_ETA_NBLOCKS, &state);

    ctr = rej_eta(a->coeffs, DILITHIUM_N, buf, buflen); // rejection sampling을 통해 비밀벡터의 계수들을 생성
                                                        // rej_eta 함수에서는 1 byte(8 bit)를 최대 2개의 계수로 생성할 수 있기 때문에 한 번에 통과할 수도 있음
    while (ctr < DILITHIUM_N)
    { // 그 계수를 모두 채울때 까지 rejection sampling을 진행
        stream256_squeezeblocks(buf, 1, &state);
        ctr += rej_eta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, STREAM256_BLOCKBYTES);
    }
    stream256_release(&state);
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_gamma1(poly *a, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    uint8_t buf[POLY_UNIFORM_GAMMA1_NBLOCKS * STREAM256_BLOCKBYTES];
    stream256_state state;

    stream256_init(&state, seed, nonce);
    stream256_squeezeblocks(buf, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
    stream256_release(&state);
    PQCLEAN_DILITHIUM2_CLEAN_polyz_unpack(a, buf); // y, buf
}

void PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(poly *c, const uint8_t seed[SEEDBYTES])
{
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[SHAKE256_RATE];
    shake256incctx state;

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, seed, SEEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf, sizeof buf, &state);      // seed( H(mu | w1) ) 를 이용해서 challenge 값 생성

    signs = 0;
    for (i = 0; i < 8; ++i)
    {
        signs |= (uint64_t)buf[i] << 8 * i;             // signs에 생성된 buf를 8개씩 64bit를 저장한 후
    }
    pos = 8;                                            // signs에서 8개의 buf를 읽었기 때문에 pos는 8부터 시작

    for (i = 0; i < DILITHIUM_N; ++i)                   
    {
        c->coeffs[i] = 0;                               // 저장하고자 하는 challenge값인 c를 모두 0으로 변경해주고
    }
    for (i = DILITHIUM_N - TAU; i < DILITHIUM_N; ++i)   // 256 - TAU ~ 255 까지 늘어나는 i 값에 대해서
    {
        do
        {
            if (pos >= SHAKE256_RATE)                   // 만약, pos 값이 shake256 해시함수의 출력크기 보다 커지게 되면, 새로운 shake256값을 추출
            {
                shake256_inc_squeeze(buf, sizeof buf, &state);
                pos = 0;                                // 이번에는 signs에 8개의 shake256결과값을 얻어오지 않았기 때문에 pos = 0 부터 시작함
            }

            b = buf[pos++];                             // b에 buf값 (shake256의 결과값)을 하나씩 가져오게
        } while (b > i);                                // b의 값이 i값보다 작을 때까지 계속해서 실행함 (i값보다 크다면 재실행)

        c->coeffs[i] = c->coeffs[b];                    // c의 coef[i]의 값을 c의 coef[b]로 변경                        (즉, 현재 변경하고자 하는 coef[b]값에 어떠한 값이 이미 있다면 현재의 i값으로 그 값을 옮겨주는 행위인 것)
        c->coeffs[b] = 1 - 2 * (signs & 1);             // c의 coef[b]는 signs의 하위 1bit가 1 -> -1, 0 -> 1 로 변경    
        signs >>= 1;                                    // signs >> 1로 signs의 마지막 bit를 그 앞의 bit로 변경해줌
    }
    shake256_inc_ctx_release(&state);
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)(DILITHIUM_L * nonce + i));
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_reduce(polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_invntt_tomont(polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u, const polyvecl *v)
{
    unsigned int i;
    poly t;

    PQCLEAN_DILITHIUM2_CLEAN_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (i = 1; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        PQCLEAN_DILITHIUM2_CLEAN_poly_add(w, w, &t);
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_polyvecl_chknorm(const polyvecl *v, int32_t bound)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_L; ++i)
    {                                           // z= c*s1+y, GAMMA1 - BETA
        if (PQCLEAN_DILITHIUM2_CLEAN_poly_chknorm(&v->vec[i], bound))   // PQCLEAN_DILITHIUM2_CLEAN_poly_chknorm 함수가 true라면 1을 반환하여 rej로 돌아가도록 함
        {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_uniform_eta(polyveck *v, const uint8_t seed[CRHBYTES], uint16_t nonce)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_uniform_eta(&v->vec[i], seed, nonce++);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_reduce(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_caddq(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_shiftl(polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_shiftl(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_invntt_tomont(&v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_polyveck_chknorm(const polyveck *v, int32_t bound)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        if (PQCLEAN_DILITHIUM2_CLEAN_poly_chknorm(&v->vec[i], bound))
        {
            return 1;
        }
    }

    return 0;
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);  // w1, w0, w
    }
}

unsigned int PQCLEAN_DILITHIUM2_CLEAN_polyveck_make_hint(polyveck *h, const polyveck *v0, const polyveck *v1)
{
    unsigned int i, s = 0;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        s += PQCLEAN_DILITHIUM2_CLEAN_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }

    return s;
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyveck_pack_w1(uint8_t r[DILITHIUM_K * POLYW1_PACKEDBYTES], const polyveck *w1)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyw1_pack(&r[i * POLYW1_PACKEDBYTES], &w1->vec[i]);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(polyvecl mat[DILITHIUM_K], const uint8_t rho[SEEDBYTES])
{
    unsigned int i, j;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        for (j = 0; j < DILITHIUM_L; ++j)
        {
            PQCLEAN_DILITHIUM2_CLEAN_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[DILITHIUM_K], const polyvecl *v)
{
    unsigned int i;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_pack_pk(uint8_t pk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        pk[i] = rho[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyt1_pack(pk + i * POLYT1_PACKEDBYTES, &t1->vec[i]); // 10bit 4개 -> 8bit 5개로 pack을 진행
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES])
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        rho[i] = pk[i];
    }
    pk += SEEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyt1_unpack(&t1->vec[i], pk + i * POLYT1_PACKEDBYTES);
    }
}

// rho | K | tr | s1 | s2 | t0 pack
void PQCLEAN_DILITHIUM2_CLEAN_pack_sk(uint8_t sk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES], const uint8_t rho[SEEDBYTES], const uint8_t tr[SEEDBYTES], const uint8_t key[SEEDBYTES], const polyveck *t0, const polyvecl *s1, const polyveck *s2)
{
    unsigned int i;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        sk[i] = rho[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        sk[i] = key[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        sk[i] = tr[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s1->vec[i]);   // 3bit 8개 -> 8bit 3개로 변경하는 pack
    }
    sk += DILITHIUM_L * POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyeta_pack(sk + i * POLYETA_PACKEDBYTES, &s2->vec[i]);
    }
    sk += DILITHIUM_K * POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyt0_pack(sk + i * POLYT0_PACKEDBYTES, &t0->vec[i]); // 13bit 8개 -> 8bit 13개로 변경하는 pack
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_unpack_sk(uint8_t rho[SEEDBYTES], uint8_t tr[SEEDBYTES], uint8_t key[SEEDBYTES], polyveck *t0, polyvecl *s1, polyveck *s2, const uint8_t sk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES])
{
    unsigned int i;

    // sk는 rho | K | tr | pack(s1) | pack(s2) | pack(t0) 로 이루어져 있음
    for (i = 0; i < SEEDBYTES; ++i)
    {
        rho[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        key[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        tr[i] = sk[i];
    }
    sk += SEEDBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyeta_unpack(&s1->vec[i], sk + i * POLYETA_PACKEDBYTES); // 8bit 3개 -> 3bit 8개
    }
    sk += DILITHIUM_L * POLYETA_PACKEDBYTES;    // sk의 현재 위치를 변경해주고

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyeta_unpack(&s2->vec[i], sk + i * POLYETA_PACKEDBYTES);
    }
    sk += DILITHIUM_K * POLYETA_PACKEDBYTES;

    for (i = 0; i < DILITHIUM_K; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyt0_unpack(&t0->vec[i], sk + i * POLYT0_PACKEDBYTES);   // 8bit 13개 -> 13bit 8개
    }
}

void PQCLEAN_DILITHIUM2_CLEAN_pack_sig(uint8_t sig[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES], const uint8_t c[SEEDBYTES], const polyvecl *z, const polyveck *h)
{
    unsigned int i, j, k;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        sig[i] = c[i];
    }
    sig += SEEDBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyz_pack(sig + i * POLYZ_PACKEDBYTES, &z->vec[i]);
    }
    sig += DILITHIUM_L * POLYZ_PACKEDBYTES;

    /* Encode h */
    for (i = 0; i < OMEGA + DILITHIUM_K; ++i)
    {
        sig[i] = 0;
    }

    k = 0;
    for (i = 0; i < DILITHIUM_K; ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            if (h->vec[i].coeffs[j] != 0)
            {
                sig[k++] = (uint8_t)j; // 1인 항의 위치를 저장하고
            }
        }

        sig[OMEGA + i] = (uint8_t)k; // 각 다항식에서 1인 항의 개수가 몇개인지 저장
    }
}

int PQCLEAN_DILITHIUM2_CLEAN_unpack_sig(uint8_t c[SEEDBYTES], polyvecl *z, polyveck *h, const uint8_t sig[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES])
{
    unsigned int i, j, k;

    for (i = 0; i < SEEDBYTES; ++i)
    {
        c[i] = sig[i];
    }
    sig += SEEDBYTES;

    for (i = 0; i < DILITHIUM_L; ++i)
    {
        PQCLEAN_DILITHIUM2_CLEAN_polyz_unpack(&z->vec[i], sig + i * POLYZ_PACKEDBYTES);
    }
    sig += DILITHIUM_L * POLYZ_PACKEDBYTES;

    /* Decode h */
    k = 0;
    for (i = 0; i < DILITHIUM_K; ++i)
    {
        for (j = 0; j < DILITHIUM_N; ++j)
        {
            h->vec[i].coeffs[j] = 0;
        }

        if (sig[OMEGA + i] < k || sig[OMEGA + i] > OMEGA)
        {
            return 1;
        }

        for (j = k; j < sig[OMEGA + i]; ++j)
        {
            /* Coefficients are ordered for strong unforgeability */
            if (j > k && sig[j] <= sig[j - 1])
            {
                return 1;
            }
            h->vec[i].coeffs[sig[j]] = 1;
        }

        k = sig[OMEGA + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for (j = k; j < OMEGA; ++j)
    {
        if (sig[j])
        {
            return 1;
        }
    }

    return 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
{
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES]; // rho, rho', K를 저장할 공간
    uint8_t tr[SEEDBYTES];                     // rho, t1을 연접하여 SHAKE256을 통해 생성할 tr의 공간
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[DILITHIUM_K]; // 공개 행렬 A를 의미함
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes_win32_randombytes(seedbuf, SEEDBYTES);               // rho, rho', K를 생성할 random seed 생성
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES); // SHAKE256을 통해 1024 bit짜리 bit 배열을 생성
    rho = seedbuf;                                                   // 맨 앞 256bit를 rho
    rhoprime = rho + SEEDBYTES;                                      // 그 뒤 512bit를 rhoprime
    key = rhoprime + CRHBYTES;                                       // 맨 뒤 256bit를 K로 함

    /* Expand matrix */
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho); // 공개 행렬 seed값 rho를 통해 공개 행렬 A 생성 -> NTT 도메인에 올라가 있는 상태로 생성함

    /* Sample short vectors s1 and s2 */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);           // rejection sampling과 seed값 rhoprime을 통해 s1 생성
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_uniform_eta(&s2, rhoprime, DILITHIUM_L); // 위와 마찬가지

    /* Matrix-vector multiplication */
    s1hat = s1;                                                                     // s1은 이후 secret key를 pack하는데 사용해야 하기 때문에, s1hat에 s1을 집어 넣고 NTT 도메인 영역으로 보내게 됨
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1hat);                                  // s1을 NTT 도메인 영역으로 변경
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat); // t = A * s1
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&t1);                                  // t mod Q
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&t1);                           // t을 InvNTT

    /* Add error vector s2 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(&t1, &t1, &s2); // t = t + s2

    /* Extract t1 and write public key */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&t1);                 // t 의 범위를 0 ~ q-1 로 변경
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_power2round(&t1, &t0, &t1); // t = t1 * 2^d + t0 f로 t1, t0 의 값을 구해주고
    PQCLEAN_DILITHIUM2_CLEAN_pack_pk(pk, rho, &t1);               // pk = 공개행렬 A의 seed(rho) || pack(t1) 으로 pk를 생성

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, SEEDBYTES, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES); // tr = H(rho, t1)
    PQCLEAN_DILITHIUM2_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);           // sk = rho || tr || K || pack(t0) || pack(s1) || pack(s2)

    return 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    unsigned int n;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];  // rho, K, tr, mu, rho'을 저장하는 공간 (여기에서 rho'은 key gen에서의 rho'이 아니라 y행렬을 생성하는 seed값임)
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    polyvecl mat[DILITHIUM_K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_DILITHIUM2_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);    // sk = rho | tr | K | t0 | s1 | s2를 통해 각 값을 얻어주게 됨 

    /* Compute CRH(tr, msg) */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES); // H(tr)
    shake256_inc_absorb(&state, m, mlen);       // H(tr | m)
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state); // mu = H(tr | m)
    shake256_inc_ctx_release(&state);

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);    // rho'을 통해 y행렬 seed를 생성 (rho' = H ( K | mu)) (K 와 mu는 이어져 있기 때문에 넣는 길이를 두개를 포함하는 것으로 두개를 집어넣어줌)

    /* Expand matrix and transform vectors */
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);   // rho를 통해 A행렬 생성
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1); // s1 NTT 변환
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&s2); // s2 NTT 변환
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&t0); // t0 NTT 변환

rej:
    /* Sample intermediate vector y */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);    // rho'을 통해 y행렬 생성

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);                                  // y행렬 NTT 변환
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z); // w = Ay
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w1);                              // w 감산
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&w1);                       // w InvNTT 변환

    /* Decompose w and call the random oracle */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&w1);                               // w 범위를 -q/2 ~ q/2 -> 0 ~ q 로 변환
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_decompose(&w1, &w0, &w1);                 // w = w1 * 2gamma2 + w0 로 w1, w0를 계산 (이 때 w1은 6bit 표현임)
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pack_w1(sig, &w1);                        // sig = pack(w1)

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);                                  // H(mu)
    shake256_inc_absorb(&state, sig, DILITHIUM_K * POLYW1_PACKEDBYTES);         // H(mu | w1)
    shake256_inc_finalize(&state);                                              
    shake256_inc_squeeze(sig, SEEDBYTES, &state);                               // sig = H(mu | w1)
    shake256_inc_ctx_release(&state);
    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(&cp, sig);                          // -1 or +1 인 계수가 TAU개인 challenge 다항식 c생성                       
    PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&cp);                                     // c NTT 변환

    /* Compute z, reject if it reveals secret */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);  // z = c * s1
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_invntt_tomont(&z);                        // z InvNTT 변환
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(&z, &z, &y);                          // z = z + y (z = c*s1 + y)
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_reduce(&z);                               // z 감산
    if (PQCLEAN_DILITHIUM2_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA))           // 만약, z의 계수의 절대값이 gamma1 - eta * tau 보다 크다면(함수의 결과값이 true라면 rej, false라면 다음 단계 진행)
    {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);  // h = c * s2
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&h);                        // c * s2 InvNTT
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_sub(&w0, &w0, &h);                        // w0 = w0 - c * s2
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w0);                              // w0 감산
    if (PQCLEAN_DILITHIUM2_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA))          // 만약 w0 - c * s2 의 계수의 절대값이 
    {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_DILITHIUM2_CLEAN_polyveck_chknorm(&h, GAMMA2))
    {
        goto rej;
    }

    PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_DILITHIUM2_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA)
    {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_DILITHIUM2_CLEAN_pack_sig(sig, sig, &z, &h);
    *siglen = PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES;
    return 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk)
{
    size_t i;

    for (i = 0; i < mlen; ++i)
    {
        sm[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i]; // m에 있는 message를 뒤에서 부터 저장
    }                                                                               // 결국에는 sm의 마지막 MLEN bytes를 M으로 채우는 작업임
    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sm, smlen, sm + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES, mlen, sk);
    *smlen += mlen;
    return 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk)
{
    unsigned int i;
    uint8_t buf[DILITHIUM_K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl mat[DILITHIUM_K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    if (siglen != PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES)
    {
        return -1;
    }

    PQCLEAN_DILITHIUM2_CLEAN_unpack_pk(rho, &t1, pk);
    if (PQCLEAN_DILITHIUM2_CLEAN_unpack_sig(c, &z, &h, sig))
    {
        return -1;
    }
    if (PQCLEAN_DILITHIUM2_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA))
    {
        return -1;
    }

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, SEEDBYTES, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&cp);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_DILITHIUM2_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify PQCLEAN_DILITHIUM2_CLEAN_challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, DILITHIUM_K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i)
    {
        if (c[i] != c2[i])
        {
            return -1;
        }
    }

    return 0;
}

int PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
    size_t i;

    if (smlen < PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES)
    {
        goto badsig;
    }

    *mlen = smlen - PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES;
    if (PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sm, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES, sm + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES, *mlen, pk))
    {
        goto badsig;
    }
    else
    {
        /* All good, copy msg, return 0 */
        for (i = 0; i < *mlen; ++i)
        {
            m[i] = sm[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES + i];
        }
        return 0;
    }

badsig:
    /* Signature verification failed */
    *mlen = (size_t)-1;
    for (i = 0; i < smlen; ++i)
    {
        m[i] = 0;
    }

    return -1;
}

int main()
{
    size_t i, j;
    int ret;
    size_t mlen, smlen;
    uint8_t b;
    uint8_t m[MLEN + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES];  // 실제         message
    uint8_t m2[MLEN + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES]; // verify에 있는 message
    uint8_t sm[MLEN + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES]; // sign에 있는  message
    uint8_t pk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES];

    /*
        for(int i = 0; i < MLEN; i++)
        {
            printf("0x%02x ", m[i]);
            if(i % 8 == 7)
                printf("\n");
        }

        randombytes_win32_randombytes(m, MLEN); // sign 과정에서 사용할 message(M) 생성, 이후 sign에서 tr과 연접하여 SHAKE256을 통해 512bit(64byte)로 변경

        printf("\nAfter random bytes\n");

        for(int i = 0; i < MLEN; i++)
        {
            printf("0x%02x ", m[i]);
            if(i % 8 == 7)
                printf("\n");
        }
    */

    randombytes_win32_randombytes(m, MLEN); // sign 과정에서 사용할 message(M) 생성, 이후 sign에서 tr과 연접하여 SHAKE256을 통해 512bit(64byte)로 변경

    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk);                       // key 생성
    PQCLEAN_DILITHIUM2_CLEAN_crypto_sign(sm, &smlen, m, MLEN, sk);              // sign 생성
    ret = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(m2, &mlen, sm, smlen, pk);

    if (ret)
    {
        fprintf(stderr, "Verification failed\n");
        return -1;
    }
    if (smlen != MLEN + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES)
    {
        fprintf(stderr, "Signed message lengths wrong\n");
        return -1;
    }
    if (mlen != MLEN)
    {
        fprintf(stderr, "Message lengths wrong\n");
        return -1;
    }
    for (j = 0; j < MLEN; ++j)
    {
        if (m2[j] != m[j])
        {
            fprintf(stderr, "Messages don't match\n");
            return -1;
        }
    }

    randombytes_win32_randombytes((uint8_t *)&j, sizeof(j));
    do
    {
        randombytes_win32_randombytes(&b, 1);
    } while (!b);

    sm[j % (MLEN + PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES)] += b;
    ret = PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_open(m2, &mlen, sm, smlen, pk);
    if (!ret)
    {
        fprintf(stderr, "Trivial forgeries possible\n");
        return -1;
    }

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES);
    printf("CRYPTO_BYTES = %d\n", PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES);

    return 0;
}
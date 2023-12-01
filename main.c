#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <omp.h>
#include <sys/random.h>
#include <m4ri/m4ri.h>
#include <openssl/evp.h>
#include <gsl/gsl_spmatrix.h>

// Elisabeth4 and toy cipher constants
const uint8_t S1[16] = {3, 2, 6, 12, 10, 0, 1, 11, 13, 14, 10, 4, 6, 0, 15, 5};
const uint8_t S2[16] = {4, 11, 4, 4, 4, 15, 9, 12, 12, 5, 12, 12, 12, 1, 7, 4};
const uint8_t S3[16] = {11, 10, 12, 2, 2, 11, 13, 14, 5, 6, 4, 14, 14, 5, 3, 2};
const uint8_t S4[16] = {5, 9, 13, 2, 11, 10, 12, 5, 11, 7, 3, 14, 5, 6, 4, 11};
const uint8_t S5[16] = {3, 0, 11, 8, 13, 14, 13, 11, 13, 0, 5, 8, 3, 2, 3, 5};
const uint8_t S6[16] = {8, 13, 12, 12, 3, 15, 12, 7, 8, 3, 4, 4, 13, 1, 4, 9};
const uint8_t S7[16] = {4, 2, 9, 13, 10, 12, 10, 7, 12, 14, 7, 3, 6, 4, 6, 9};
const uint8_t S8[16] = {10, 2, 5, 5, 3, 13, 15, 1, 6, 14, 11, 11, 13, 3, 1, 15};

const uint8_t toyS1[16] = {3, 0, 6, 2, 5, 8, 2, 6};
const uint8_t toyS2[16] = {4, 2, 4, 1, 4, 6, 4, 7};
const uint8_t toyS3[16] = {6, 1, 7, 4, 2, 7, 1, 4};
const uint8_t toyS4[16] = {4, 2, 6, 1, 4, 6, 2, 7};
const uint8_t toyS5[16] = {2, 2, 4, 4, 6, 6, 4, 4};
const uint8_t toyS6[16] = {7, 1, 4, 1, 1, 7, 4, 7};
const uint8_t toyS7[16] = {0, 5, 4, 2, 8, 3, 4, 6};
const uint8_t toyS8[16] = {3, 4, 1, 7, 5, 4, 7, 1};

const uint8_t ltoyS1[16] = {3, 0, 2, 2, 1, 0, 2, 2};
const uint8_t ltoyS2[16] = {0, 2, 0, 1, 0, 2, 0, 3};
const uint8_t ltoyS3[16] = {2, 1, 3, 0, 2, 3, 1, 0};
const uint8_t ltoyS4[16] = {0, 2, 2, 1, 0, 2, 2, 3};
const uint8_t ltoyS5[16] = {2, 2, 0, 0, 2, 3, 0, 0};
const uint8_t ltoyS6[16] = {3, 1, 0, 1, 1, 3, 0, 3};
const uint8_t ltoyS7[16] = {0, 1, 0, 2, 0, 3, 0, 2};
const uint8_t ltoyS8[16] = {3, 0, 1, 3, 1, 0, 3, 1};

// Considered variants
typedef struct _variant {
    int n; // number of elements in the sboxes
    int s; // size in bits of sboxes
    int N; // number of nibbles in state
    int T; // number of g functions per output. 5*T <= N
    // Sboxes
    const uint8_t *S1;
    const uint8_t *S2;
    const uint8_t *S3;
    const uint8_t *S4;
    const uint8_t *S5;
    const uint8_t *S6;
    const uint8_t *S7;
    const uint8_t *S8;
} variant;

// Define all the possible variants
variant Elisabeth4 = {16, 4, 256, 12, S1, S2, S3, S4, S5, S6, S7, S8};
variant lily4 = {16, 4, 5, 1, S1, S2, S3, S4, S5, S6, S7, S8};
variant lily3 = {8, 3, 5, 1, toyS1, toyS2, toyS3, toyS4, toyS5, toyS6, toyS7, toyS8};
variant lily3_10_2 = {8, 3, 10, 2, toyS1, toyS2, toyS3, toyS4, toyS5, toyS6, toyS7, toyS8};
variant lily3_12_2 = {8, 3, 12, 2, toyS1, toyS2, toyS3, toyS4, toyS5, toyS6, toyS7, toyS8};
variant lily3_30_2 = {8, 3, 30, 2, toyS1, toyS2, toyS3, toyS4, toyS5, toyS6, toyS7, toyS8};
variant lily2 = {4, 2, 5, 1, ltoyS1, ltoyS2, ltoyS3, ltoyS4, ltoyS5, ltoyS6, ltoyS7, ltoyS8};

// Choose the variant to attack (active variant)
variant *activeVariant = &lily3_12_2;

// XOF constants
unsigned char *C0 = (unsigned char *) "0123456789abcdef";
unsigned char *C1 = (unsigned char *) "fedcba9876543210";

// Elisabeth test key
unsigned char KEY[256] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
};

// Elisabeth test IV
unsigned char *IV = (unsigned char *) "0000000000000000";

// Nibble order types and global variables
typedef uint16_t nibble_t[4];
nibble_t *nibbles = NULL;
size_t nibbles_len = 0;
int nibbleIndex[256][2];

// Nibble permutations
nibble_t permutations[24] = {
    {0, 1, 2, 3},
    {0, 1, 3, 2},
    {0, 2, 1, 3},
    {0, 2, 3, 1},
    {0, 3, 1, 2},
    {0, 3, 2, 1},
    {1, 0, 2, 3},
    {1, 0, 3, 2},
    {1, 2, 0, 3},
    {1, 2, 3, 0},
    {1, 3, 0, 2},
    {1, 3, 2, 0},
    {2, 0, 1, 3},
    {2, 0, 3, 1},
    {2, 1, 0, 3},
    {2, 1, 3, 0},
    {2, 3, 0, 1},
    {2, 3, 1, 0},
    {3, 0, 1, 2},
    {3, 0, 2, 1},
    {3, 1, 0, 2},
    {3, 1, 2, 0},
    {3, 2, 0, 1},
    {3, 2, 1, 0}
};

/*
 * An implementention of Elisabeth ciphers
 */

// AES encryption
void encrypt_aes(unsigned char *plaintext, unsigned char * key,
        unsigned char * ciphertext) {
    int length = 0;

    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new()");
        exit(-1);
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        perror("EVP_EncryptInit_ex()");
        exit(-1);
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, 16) || length != 16) {
        perror("EVP_EncryptUpdate()");
        exit(-1);
    }
    EVP_CIPHER_CTX_free(ctx);
}

typedef struct _XOF_state {
    unsigned char XOF_K[16];
    unsigned char XOF_R[16];
    int XOF_offset;
} XOF_state;

//   init: init XOF_K with IV
void XOF_init(XOF_state *x, unsigned char *iv) {
    int i;
    for (i = 0; i < 16; i++) x->XOF_K[i] = iv[i];
    x->XOF_offset = 128;
}

//   update: refresh XOF_K and XOF_R, and update number of fresh bits in R
void XOF_update(XOF_state *x) {
    int i;
    unsigned char tmp[16];
    encrypt_aes(C0, x->XOF_K, tmp);
    encrypt_aes(C1, x->XOF_K, x->XOF_R);
    for (i = 0; i < 16; i++) x->XOF_K[i] = tmp[i];
    x->XOF_offset = 0;
}

//  bits: extract an nbit integer from the bitstream produced by the XOF, updating the state when needed
unsigned int XOF_bits(XOF_state *x, int n) {
    int u, r, s, p=0;
    unsigned int res = 0;
    while (n > 0) {
        if (x->XOF_offset == 128) XOF_update(x);
        // number of bits used in the current byte
        u = x->XOF_offset % 8;
        // number of bits remaining in the current byte
        r = 8 - u;
        // number of bits to transfer
        s = r < n ? r : n;
        // transfer bits to result
        res ^= ((x->XOF_R[x->XOF_offset >> 3] >> u) % (1 << s)) << p;
        p += s;
        n -= s;
        x->XOF_offset += s;
    }
    return res;
}

//  int: produce an integer in an interval [a,b[, uses rejection sampling
unsigned int XOF_int(XOF_state *x, unsigned int a, unsigned int b) {
    unsigned int r, n = __builtin_clz(1) + 1 - __builtin_clz(b-a-1);
    //printf("%u %d\n", b-a, n);
    while ((r = XOF_bits(x, n)) >= b-a);
    return a + r;
}

// Elisabeth h function
uint8_t h(const uint8_t x1, const uint8_t x2, const uint8_t x3, const uint8_t x4, variant *algo) {
    const uint8_t mask = algo->n-1;
    const uint8_t a = (x1 + x2) & mask;
    const uint8_t b = (x2 + x3) & mask;
    const uint8_t c = (x3 + x4) & mask;
    const uint8_t d = (x4 + x1) & mask;

    const uint8_t S1a = algo->S1[a];
    const uint8_t S2b = algo->S2[b];
    const uint8_t S3c = algo->S3[c];
    const uint8_t S4d = algo->S4[d];

    const uint8_t A = algo->S5[ (x1 + S2b + S3c) & mask ];
    const uint8_t B = algo->S6[ (x2 + S3c + S4d) & mask ];
    const uint8_t C = algo->S7[ (x3 + S4d + S1a) & mask ];
    const uint8_t D = algo->S8[ (x4 + S1a + S2b) & mask ];
    return A+B+C+D;
}

// Elisabeth state
#define MAX_ELI_N   256
typedef struct _ELI_state {
    variant *algo;
    XOF_state x;
    unsigned char k[MAX_ELI_N];
    int perm[MAX_ELI_N];
    unsigned char w[MAX_ELI_N];
    unsigned char z;
} ELI_state;

// Elisabeth init function, init XOF and key register
void ELISABETH_init(ELI_state *es, variant *algo, unsigned char *key, unsigned char *iv) {
    int i;
    es->algo = algo;
    XOF_init(&(es->x), iv);
    for (i = 0; i < algo->N; i++) {
        es->k[i] = key[i];
        es->perm[i] = i;
        es->w[i] = 0;
    }
}

// Elisabeth next function, update key register, and compute output nibble
unsigned char ELISABETH_next(ELI_state *es) {
    int j, tmp;
    unsigned int r, ww;
    variant *algo = es->algo;
    unsigned char *k = es->k;
    int *perm = es->perm;
    unsigned char *w = es->w;
    // update permutation and masks
    for (j = 0; j < 5*algo->T; j++) {
        r = XOF_int(&(es->x), j, algo->N);
        ww = XOF_bits(&(es->x), algo->s);
        // swap positions j and r
        tmp = perm[j];
        perm[j] = perm[r];
        perm[r] = tmp;
        // update mask of position j
        w[perm[j]] = (w[perm[j]] + ww) % algo->n;
    }
    // compute output
    es->z = 0;
    for (j = 0; j < algo->T; j++)
        es->z = (es->z + h(
                (k[perm[5*j]]   + w[perm[5*j]])   % algo->n,
                (k[perm[5*j+1]] + w[perm[5*j+1]]) % algo->n,
                (k[perm[5*j+2]] + w[perm[5*j+2]]) % algo->n,
                (k[perm[5*j+3]] + w[perm[5*j+3]]) % algo->n, algo) +
                k[perm[5*j+4]] + w[perm[5*j+4]]) % algo->n;
    return es->z;
}

/*
 * Study of the ANF of the nonlinear function g
 */

// applies Mobius transform on the rows of matrix M
void applyMobius(mzd_t *M) {
    int j, k, l;
    mzd_t *tmp;
    // Transpose to get one ANF per column
    printf("Mobius: transposing...");
    fflush(stdout);
    tmp = mzd_transpose(NULL, M);
    // Apply Mobius transform on the columns
    printf("computing...");
    fflush(stdout);
    for (l = 1; l < tmp->nrows; l *= 2) {
        printf(".");
        fflush(stdout);
        for (k = 0; k < tmp->nrows; k += 2*l) {
            for (j = 0; j < l; j++) {
                mzd_row_add(tmp, k+j, k+j+l);
            }
        }
    }

    // Transpose the result to get one ANF per row
    printf("transposing...");
    fflush(stdout);
    mzd_transpose(M, tmp);
    printf("done\n");
    fflush(stdout);
    mzd_free(tmp);
}

// generate an identity matrix of given size
mzd_t *identityMatrix(int N) {
    mzd_t *M = mzd_init(N, N);
    int i, j;
    for (i = 0; i < N; i++) {
        for (j = 0; j < N; j++) {
            mzd_write_bit(M, i, j, i == j ? 1 : 0);
        }
    }
    return M;
}

// build the matrix of the function h from variant algo, with input nibble permutation
// given by perm. perm = NULL corresponds to the identity permutation
// x_i is sent to entry p[i] of h
// that is to say, for all (m_0, m_1, m_2, m3), construct the ANF of the functions :
//    (x_0, x_1, x_2, x_3) -> h(x_p^-1[0] + m_0, x_p^-1[1] + m_1, x_p^-1[2] + m_2, x_p^-1[3] + m_3)
// m_i is the mask applied to entry i of h
mzd_t *constructMatrix(variant *algo, uint16_t *perm) {

    nibble_t defaultperm = {0, 1, 2, 3};
    // NN == algo->n ^ 4
    int NN = algo->n;
    NN = NN*NN;
    NN = NN*NN;
    mzd_t *TT = mzd_init(NN, NN);
    uint32_t row = 0;
    uint32_t col = 0;
    uint16_t *p;
    if (perm == NULL)
        p = defaultperm;
    else
        p = perm;
    uint8_t x[4];
    uint8_t m[4];
    uint8_t s[4];

    printf("Building Matrix for permutation [ %d %d %d %d ]\n", p[0], p[1], p[2], p[3]);
    // create Truth table, one row per function
    for (m[0] = 0; m[0] < algo->n; ++m[0]) {
        printf("%x", m[0]);
        fflush(stdout);
        for (m[1] = 0; m[1] < algo->n; ++m[1]) {
            for (m[2] = 0; m[2] < algo->n; ++m[2]) {
                for (m[3] = 0; m[3] < algo->n; ++m[3]) {

                    // For one specific, mask (m1, m2, m3, m4),
                    // with the thruth table of the Boolean function
                    // (x1, x2, x3, x4) -> lsb(h(x1, x2, x3, x4))
                    // in a row of TT matrix of dimension NxN

                    col = 0;
                    for (x[0] = 0; x[0] < algo->n; ++x[0]) {
                        s[p[0]] = (x[0] + m[p[0]]) & 0xf;

                        for (x[1] = 0; x[1] < algo->n; ++x[1]) {
                            s[p[1]] = (x[1] + m[p[1]]) & 0xf;

                            for (x[2] = 0; x[2] < algo->n; ++x[2]) {
                                s[p[2]] = (x[2] + m[p[2]]) & 0xf;

                                for (x[3] = 0; x[3] < algo->n; ++x[3]) {
                                    s[p[3]] = (x[3] + m[p[3]]) & 0xf;

                                    // Evaluate the Elisabeth4 function
                                    const BIT lsb = h(s[0], s[1], s[2], s[3], algo) & 1;
                                    mzd_write_bit(TT, row, col, lsb);

                                    // Next column
                                    col++;

                                }/*l*/
                            }/*k*/
                        }/*j*/
                    }/*i*/

                    // Next row (i.e., next truth table)
                    row++;

                }/*m4*/
            }/*m3*/
        }/*m2*/
    }/*m1*/
    printf("\n");

    // Apply Mobius transform to get one ANF per row
    applyMobius(TT);
    return TT;
}

// build the matrix of the antler function H from variant algo
// This is is for testing purposes only, the choice of the three involved Sboxes
// is hardcoded
mzd_t *constructHMatrix(variant *algo) {

    mzd_t *TT = mzd_init(1 << 11, 1 << 11);
    uint32_t row = 0;
    uint32_t col = 0;
    uint8_t x[4];
    uint8_t m[4];

    // create Truth table, one row per function
    for (m[3] = 0; m[3] < 8; ++m[3]) {
        printf("%x", m[3]);
        fflush(stdout);
        for (m[1] = 0; m[1] < algo->n; ++m[1]) {
            for (m[0] = 0; m[0] < algo->n; ++m[0]) {

                // For one specific, mask (m1, m2, m3, m4),
                // with the thruth table of the Boolean function
                // (x1, x2, x3, x4) -> lsb(h(x1, x2, x3, x4))
                // in a row of TT matrix of dimension NxN

                col = 0;
                for (uint8_t i = 0; i < 8; ++i) {
                    x[3] = (i + m[3]) & 0xf;

                    for (uint8_t j = 0; j < algo->n; ++j) {
                        x[1] = (j + m[1]) & 0xf;

                        for (uint8_t k = 0; k < 16; ++k) {
                            x[0] = (k + m[0]) & 0xf;

                            // Evaluate the Elisabeth4 H function
                            uint8_t Sa = algo->S2[(x[0]) & 0xf];
                            uint8_t Sb = algo->S3[(x[1]) & 0xf];
                            uint8_t A = algo->S7[(Sa + Sb + x[3]) & 0xf];
                            mzd_write_bit(TT, row, col, A & 1);

                            // Next column
                            col++;

                        }/*k*/
                    }/*j*/
                }/*i*/

                // Next row (i.e., next truth table)
                row++;

            }/*m4*/
        }/*m3*/
    }/*m1*/

    return TT;
}

// Degree Reverse Lexographical order on monomials encoded in integers
int drevlex(const void *a, const void *b, void *n) {
    int ia, ib;
    int ha, hb;
    ia = *((int *) a);
    ib = *((int *) b);
    ha = __builtin_popcount(ia);
    hb = __builtin_popcount(ib);
    if (ia == ib) return 0;
    if (ha < hb || (ha == hb && ia < ib)) return -1;
    return 1;
}

int bitperm(int a, int n)
{
    int i, j;
    int res = 0;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < n; j++) {
            res |= ((a >> (i*n + j))&1) << (4*j+i);
        }
    }
    return res;
}

// Alternative monomial order
int sblex(const void *a, const void *b, void *n)
{
    int ia, ib, in;
    ia = *((int *) a);
    ib = *((int *) b);
    in = *((int *) n);
    if (ia == ib) return 0;
    return bitperm(ia, in) < bitperm(ib, in) ? -1 : 1;
}

// Monomial order state an initialization function
int monomialOrder[1 << 16];
mzp_t *P2NMO = NULL;

void monomial_order_init(int nvar) {
    if (P2NMO != NULL) return;
    int i, j;
    int n = 1 << nvar;
    int a[n];
    for (i = 0; i < n; i++)
        monomialOrder[i] = i;
    qsort_r(monomialOrder, n, sizeof(int), &drevlex, NULL);
    //put the monomial ordering in the form of a matrix permutation
    for (i = 0; i < n; i++) {
        a[i] = i;
    }
    P2NMO = mzp_init(n);
    for (i = 0; i < n; i++) {
        for (j = i; a[j] != monomialOrder[i]; j++);
        P2NMO->values[i] = j;
        a[j] = a[i];
        a[i] = monomialOrder[i];
    }
}

void monomial_order_free() {
    mzp_free(P2NMO);
    P2NMO = NULL;
}

typedef struct _morder {
    int n;
    int perm[1 << 16];
    int inv_perm[1 << 16];
    mzp_t *P;
    mzp_t *inv_P;
} morder;

mzp_t *perm2mzp(int *perm, int n)
{
    mzp_t *res;
    int i, j;
    int a[1 << 16];
    res = mzp_init(n);
    if (!res) return NULL;
    for (i = 0; i < n; i++)
        a[i] = i;
    for (i = 0; i < n; i++) {
        for (j = i; a[j] != perm[i]; j++);
        res->values[i] = j;
        a[j] = a[i];
        a[i] = perm[i];
    }
    return res;
}

void morder_free(morder *o)
{
    if (!o) return;
    if (o->P) mzp_free(o->P);
    if (o->inv_P) mzp_free(o->inv_P);
    free(o);
}

morder *morder_init(int nvar, int (*cmp)(const void *a, const void *b, void *arg))
{
    int i;
    morder *res = (morder *) malloc(sizeof(morder));
    res->P = NULL;
    res->inv_P = NULL;
    if (!res) return NULL;
    res->n = 1 << (4*nvar);
    // compute permutation
    for (i = 0; i < res->n; i++)
        res->perm[i] = i;
    qsort_r(res->perm, res->n, sizeof(int), cmp, &nvar);
    // compute inv perm
    for (i = 0; i < res->n; i++)
        res->inv_perm[res->perm[i]] = i;
    //put the monomial ordering in the form of a matrix permutation
    if (!(res->P = perm2mzp(res->perm, res->n))) {
        morder_free(res);
        return NULL;
    }
    if (!(res->inv_P = perm2mzp(res->inv_perm, res->n))) {
        morder_free(res);
        return NULL;
    }
    return res;
}

// utils functions
void print_nibble(nibble_t *n) {
    int i;
    printf("[");
    for (i = 0; i < 4; i++) {
        if (i > 0) printf(" ");
        printf("%3d", n[0][i]);
    }
    printf("]");
}

void print_nibbles() {
    int i;
    for (i = 0; i < nibbles_len; i++) {
        printf("%5d ", i);
        print_nibble(nibbles + i);
        printf("\n");
    }
}

int cmp_nibble(const void *a, const void *b) {
    const nibble_t *na = (nibble_t *) a;
    const nibble_t *nb = (nibble_t *) b;
    int i;
    //print_nibble(na); printf("\n");
    //print_nibble(nb); printf("\n");
    for (i = 0; i < 4; i++) {
        if (na[0][i] < nb[0][i]) return -1;
        if (na[0][i] > nb[0][i]) return 1;
    }
    return 0;
}

int cmp_int(const void *a, const void *b) {
    const int *na = (int *) a;
    const int *nb = (int *) b;
    //print_nibble(na); printf("\n");
    //print_nibble(nb); printf("\n");
    if (*na < *nb) return -1;
    if (*na > *nb) return 1;
    return 0;
}

int binary_search(void *e, void *t, size_t n, size_t size, int (*cmp)(const void *, const void *)) {
    int a, b, m, c;
    a = 0;
    b = n;
    while(b - a > 1) {
        m = (a + b) / 2;
        c = cmp(e, t + size*m);
        switch (c) {
            case -1:
                b = m;
                break;
            case 1:
                a = m;
                break;
            //case 0
            default:
                return m;
        }
    }
    if (cmp(e, t+size*a) == 0)
        return a;
    else
        return n;
}

void nibble_order_init(int N) {
    if (nibbles) return;
    int i, j, k, p = 1, q = 1, n;
    //init nibbleIndex
    for (i = 0; i < N; i++)
        nibbleIndex[i][0] = -1;
    //determine number of quadruplets of nibbles
    for (i = 0; i < 4; i++) {
        p *= (N-i);
        q *= (i+1);
    }
    n = p / q;
    //alloc tables of nibbles
    nibbles = (nibble_t *) malloc(n*sizeof(nibble_t));
    nibbles_len = n;
    //populate the nibble table
    for (i = 0; i < 4; i++) {
        nibbles[0][i] = i;
    }
    for (i = 1; i < n; i++) {
        //compute next nibble from the previous one
        //look for first movable position
        for (j = 3; j >= 0 && nibbles[i-1][j] == N-(4-j); j--);
        //create next nibble : copy previous one until position j, then fill from j
        for (k = 0; k < j; k++) nibbles[i][k] = nibbles[i-1][k];
        nibbles[i][j] = nibbles[i-1][j] + 1;
        for (k = j+1; k < 4; k++)
            nibbles[i][k] = nibbles[i][k-1] + 1;
    }
    //populate the nibbleIndex
    for (i = 0; i < N; i++) {
        for (j = 0; nibbleIndex[i][0] == -1 && j < n; j++) {
            for (k = 0; nibbleIndex[i][0] == -1 && k < 4; k++) {
                if (nibbles[j][k] == i) {
                    nibbleIndex[i][0] = j; // nibble i is in nibble set j
                    nibbleIndex[i][1] = k; // nibble i is at position k in nibble set j;
                }
            }
        }
        if (nibbleIndex[i][0] == -1) {
            printf("BUG no index found for nibble %d\n", i);
            exit(2);
        }
    }
}

void nibble_order_free() {
    free(nibbles);
    nibbles = NULL;
}

// if transpose is not zero returns transposed M matrix on which rows have been reordered
// if transpose is 0, return M matrix on whic columns have been reordered. Additionaly in this case,
// perform row echelon reduction if echelonize is not 0
mzd_t *morder_reorder_columns(mzp_t *P, mzd_t *M, int echelonize) {
    // reorder columns
    fprintf(stderr, "...reorder");
    mzd_apply_p_right(M, P);
    // and reechelonize the matrix, fully, if required
    if (echelonize){
        fprintf(stderr, "...echelonize");
        mzd_echelonize(M, 1);
    }
    fprintf(stderr, "\n");
    return M;
}

// if transpose is not zero returns transposed M matrix on which rows have been reordered
// if transpose is 0, return M matrix on whic columns have been reordered. Additionaly in this case,
// perform row echelon reduction if echelonize is not 0
mzd_t *reorderMonomials(mzd_t *M, int echelonize, int transpose) {
    mzd_t *tmp;
    rci_t rank;
    // transpose the matrix to reorder rows
    fprintf(stderr, "reorderMonomials");
    fprintf(stderr, "...transpose");
    tmp = mzd_transpose(NULL, M);
    // reorder rows
    fprintf(stderr, "...reorder");
    mzd_apply_p_left(tmp, P2NMO);
    // if transpose, free the original matrix and return directly the matrix
    if (transpose) {
        mzd_free(M);
        return tmp;
    }
    // otherwise transpose back the matrix
    fprintf(stderr, "...transpose back");
    mzd_transpose(M, tmp);
    mzd_free(tmp);
    // and reechelonize the matrix, fully, if required
    if (echelonize) {
        fprintf(stderr, "...echelonize");
        rank = mzd_echelonize(M, 1);
        fprintf(stderr, "...rank=%d", rank);
        tmp = mzd_submatrix(NULL, M, 0, 0, rank, M->ncols);
        mzd_free(M);
        M = tmp;
    }
    fprintf(stderr, "\n");
    return M;
}

void printMonomial(int i) {
    int k, l, m;
    m = monomialOrder[i];
    if (m == 0) {
        printf("1");
        return;
    }
    printf("%04x ", m);
    for (k = 0; k < 4; k++) {
        for (l = 0; l < 4; l++) {
            if (m % 2 == 1) printf("x_%d,%d", k, l);
            m >>= 1;
        }
    }
}

void printPolynomial(mzd_t *M, int i) {
    int j;
    int first = 1;
    for (j = 0; j < M->ncols; j++) {
        if(mzd_read_bit(M, i, j) == 1) {
            if (!first)
                printf(" + ");
            first = 0;
            printMonomial(j);
        }
    }
}

void monomialInfo(int i, int *mi) {
    int m = monomialOrder[i], k, l;
    for (k = 0; k < 4; k++) {
        for (l = 0; l < 4; l++) {
            if (m % 2 == 1) mi[k] |= 1;
            m >>= 1;
        }
    }
}

int polynomialInfo(mzd_t *M, int i) {
    int j;
    int hw = 0;
    int mi[4] = {0, 0, 0, 0};
    int shared;
    for (j = 0; j < M->ncols; j++) {
        if(mzd_read_bit(M, i, j) == 1) {
            hw++;
            monomialInfo(j, mi);
        }
    }
    if (mi[0] == 0 || mi[1] == 0 || mi[2] == 0 || mi[3] == 0)
        shared = 1;
    else
        shared = 0;
    printf("HW=%d %d [%d,%d,%d,%d]", hw, shared, mi[0], mi[1], mi[2], mi[3]);
    if (hw == 1) {
        printf(" ");
        printPolynomial(M, i);
    }
    return shared;
}

void missingIndependentMonomials(mzd_t *m)
{
    int i, j;
    for (i= 0,j = 0; j < m->ncols; j++) {
        if (i >= m->nrows || (mzd_read_bit(m, i, j) == 0))
            printf("Missing monomial %04x\n", monomialOrder[j]);
        if (mzd_read_bit(m, i, j) == 1) i++;
    }
}

void inspectOrderedBasis(mzd_t *M) {
    int i, j;
    int shared = 0;
    for (i = 0; i < M->nrows; i++) {
        printf("%d ", i);
        shared += polynomialInfo(M, i);
        printf("\n");
    }
    printf("dimension defaults\n");
    for (i = 0, j = 0; i < M->nrows; i++, j++) {
        while (mzd_read_bit(M, i, j) != 1) {
            printMonomial(monomialOrder[j]);
            printf("\n");
            j++;
        }
    }
    printf("shared: %d/%d\n", shared, M->nrows);
    missingIndependentMonomials(M);
}

/*
 * Implementation of a linearization attack on a toy version of Elisabeth-4
 */

void buildPolynomialBasisMatrix(variant *algo, char *variant_dir) {
    int i;
    mzd_t *mat, *mat_tmp;
    mzd_t *A = NULL;
    int rank;
    char fn[1024];
    printf("preparing building of polynomial basis matrix\n");
    monomial_order_init(algo->s*4);
    sprintf(fn, "%s/basis.png", variant_dir);
    /*       Generation of the basis matrix     */
    // allocations
    // for all permutations
    // - construct the matrix
    // - reorder its columns according to the monomial order
    // - stack it with the current matrix
    // - perform row echelonization
    for (i = 0; i < 24; i++) {
        fprintf(stderr, "------ STEP %2d --------\n", i);
        mat = constructMatrix(algo, permutations[i]);
        mat = reorderMonomials(mat, 0, 0);
        if (i == 0)
            mat_tmp = mat;
        else {
            mat_tmp = mzd_stack(NULL, A, mat);
            mzd_free(mat);
            mzd_free(A);
        }
        fprintf(stderr, "echelonization step ");
        rank = mzd_echelonize(mat_tmp, 1);
        fprintf(stderr, "current rank %d\n", rank);
        A = mzd_submatrix(NULL, mat_tmp, 0, 0, rank, mat_tmp->ncols);
        mzd_free(mat_tmp);
    }
    // Save the basis
    mzd_to_png(A, fn, 0, NULL, 0);
    // clean
    mzd_free(A);
    monomial_order_free();
}

void buildBasisMatrices(variant *algo, char *variant_dir) {
    int i;
    mzd_t *A, *tA;
    mzp_t *P, *Q;
    mzd_t *B, *tB;
    mzd_t *X, *tX;
    char fname[1024];
    int rc, rank;

    monomial_order_init(algo->s*4);
    // load A
    sprintf(fname, "%s/basis.png", variant_dir);
    A = mzd_from_png(fname, 0);
    // transpose A
    tA = mzd_transpose(NULL, A);
    mzd_free(A);
    // Prepare to solve X.A = B, using tA.tX = tB
    P = mzp_init(tA->nrows);
    Q = mzp_init(tA->ncols);
    // allocate matrix for storing solution
    X = mzd_init(A->ncols, A->nrows);
    tX = mzd_init(X->ncols, X->nrows);
    // solver preprocessing
    P = mzp_init(tA->nrows);
    Q = mzp_init(tA->ncols);
    rank = mzd_pluq(tA, P, Q, 0);
    printf("pre processing rank: %d\n", rank);

    // Express the systems in terms of the elements of the basis
    // For all permutations
    // - construct the matrix
    // - reorder its columns according to the monomial order
    // - solve a system
    for (i = 0; i < 24; i++) {
        printf("building basis for permutation number %d\n", i);
        B = constructMatrix(algo, permutations[i]);
        B = reorderMonomials(B, 0, 0);
        tB = mzd_transpose(NULL, B);
        mzd_free(B);
        rc = mzd_pluq_solve_left(tA, rank, P, Q, tB, 0, 1);
        if (rc == -1) {
            mzd_free(tB);
            fprintf(stderr, "No solution for permutation %d\n", i);
            goto free;
        }
        mzd_submatrix(tX, tB, 0, 0, tX->nrows, tX->ncols);
        mzd_transpose(X, tX);
        sprintf(fname, "%s/anf-perm-%02d.png", variant_dir, i);
        mzd_to_png(X, fname, 0, NULL, 0);
        mzd_free(tB);
    }
free:
    mzd_free(tA); mzp_free(P); mzp_free(Q);
    mzd_free(X); mzd_free(tX);
    monomial_order_free();
}

void buildBasisHMatrix(variant *algo) {
    mzd_t *B, *tB;
    mzp_t *P, *Q;
    mzd_t *W;
    mzd_t *sol, *solt;
    printf("preparing building of basis matrices\n");
    monomial_order_init(12);
    // read basis matrix shared by all permutations
    B = mzd_from_png("Hreordered.png", 0);
    // transpose it
    tB = mzd_transpose(NULL, B);
    mzd_free(B);
    // solve preprocessing
    P = mzp_init(tB->nrows);
    Q = mzp_init(tB->ncols);
    rci_t rank = mzd_pluq(tB, P, Q, 0);
    sol = mzd_init(tB->ncols, tB->nrows);
    solt = mzd_init(tB->nrows, tB->ncols);

    //reconstruct the reordered matrix
    W = constructHMatrix(algo);
    W = reorderMonomials(W, 0, 1);
    //solve the system
    mzd_pluq_solve_left(tB, rank, P, Q, W, 0, 1);
    mzd_submatrix(sol, W, 0, 0, sol->nrows, sol->ncols);
    mzd_transpose(solt, sol);
    //store the solution
    mzd_to_png(solt, "basisH.png", 0, NULL, 0);
    mzd_free(W);

    mzd_free(tB); mzp_free(P); mzp_free(Q);
    mzd_free(sol); mzd_free(solt);
    monomial_order_free();
}

void testBasisMatricesElem(variant *algo, char *variant_dir)
{
    int i;
    char buffer[1024];
    mzd_t *B, *W, *M, *C;
    monomial_order_init(algo->s*4);
    // load the basis matrices
    sprintf(buffer, "%s/basis.png", variant_dir);
    B = mzd_from_png(buffer, 0);
    for (i = 0; i < 24; i++) {
        sprintf(buffer, "%s/anf-perm-%02d.png", variant_dir, i);
        printf("Loading %s\n", buffer);
        W = mzd_from_png(buffer, 0);
        printf("Multiplication by basis matrix\n");
        M = mzd_mul(NULL, W, B, 0);
        printf("Reconstructing matrix for permutation\n");
        C = constructMatrix(algo, permutations[i]);
        C = reorderMonomials(C, 0, 0);
        printf("Consistency %s\n", mzd_equal(M, C) ? "OK" : "KO");
        mzd_free(W);
        mzd_free(M);
        mzd_free(C);
    }
    mzd_free(B);
    monomial_order_free();
}

void testBasisMatrices(variant *algo, char *variant_dir)
{
    int i, j, N = 1000;
    unsigned int w;
    unsigned int x;
    unsigned int yn[4];
    unsigned int m;
    int res = 1;
    uint8_t mv[1 << 16], pv[1 << 16], xt[4], wt[4];
    char buffer[1024];
    nibble_t *p;
    rci_t r;
    mzd_t *B, *W;
    srandom(time(NULL));
    monomial_order_init(4*algo->s);

    // load the basis matrices
    sprintf(buffer, "%s/basis.png", variant_dir);
    B = mzd_from_png(buffer, 0);
    r = B->nrows;
    i = random() % 24;
    i = 0;
    sprintf(buffer, "%s/anf-perm-%02d.png", variant_dir, i);
    printf("Testing %s\n", buffer);
    W = mzd_from_png(buffer, 0);
    p = permutations + i;
    // for all permutations recompute the matrix of ANF and express the result in terms of
    // linear combinations of columns of the basis matrix
    for (i = 0; i < N; i++) {
        // generate random mask and input
        w = random() % (1 << (4*algo->s));
        wt[3] = w % algo->n;
        wt[2] = (w >> algo->s) % algo->n;
        wt[1] = (w >> (2*algo->s)) % algo->n;
        wt[0] = (w >> (3*algo->s)) % algo->n;
        x = random() % (1 << (4*algo->s));
        xt[3] = x % algo->n;
        xt[2] = (x >> algo->s) % algo->n;
        xt[1] = (x >> (2*algo->s)) % algo->n;
        xt[0] = (x >> (3*algo->s)) % algo->n;
        yn[(*p)[0]] = (xt[0] + wt[(*p)[0]]) % algo->n;
        yn[(*p)[1]] = (xt[1] + wt[(*p)[1]]) % algo->n;
        yn[(*p)[2]] = (xt[2] + wt[(*p)[2]]) % algo->n;
        yn[(*p)[3]] = (xt[3] + wt[(*p)[3]]) % algo->n;
        // apply g
        const BIT lsb = h(yn[0], yn[1], yn[2], yn[3], algo) & 1;
        // check we get the same value from the ANF
        // first compute monomials values, usual order
        printf("Monomial values vector:");
        for (m = 0; m < (1 << (4*algo->s)); m++) {
            mv[m] = (x & m) == m ? 1 : 0;
            printf(" %d", mv[m]);
        }
        printf("\n");

        // second compute basis polynomial values
        printf("Polynomial values vector:");
        for (j = 0; j < r; j++) {
            pv[j] = 0;
            for (m = 0; m < (1 << (4*algo->s)); m++) {
                if (mzd_read_bit(B, j, m) == 1)
                    pv[j] ^= mv[monomialOrder[m]];
            }
            printf(" %d", pv[j]);
        }
        printf("\n");
        // third apply ANF
        uint8_t acc = 0;
        for (j = 0; j < r; j++) {
            if (mzd_read_bit(W, w, j) == 1) acc ^= pv[j];
        }
        // test equality
        if (acc != lsb) {
            printf("Failure on test %d\n", i);
            res = 0;
            break;
        }
    }
    mzd_free(B);
    monomial_order_free();
    printf("res: %d\n", res);
}

typedef struct _int_pair {
    int idx;
    int val;
} int_pair;

int cmp_int_pair(const void *a, const void *b)
{
    int_pair *pa, *pb;
    pa = (int_pair *) a;
    pb = (int_pair *) b;
    return cmp_int(&(pa->val), &(pb->val));
}

void int_pair_extract_idx_nibble(nibble_t *d, int_pair *s)
{
    int i;
    for (i = 0; i < 4; i++) {
        (*d)[i] = (uint16_t) s[i].idx;
    }
}

void int_pair_extract_val_nibble(nibble_t *d, int_pair *s)
{
    int i;
    for (i = 0; i < 4; i++) {
        (*d)[i] = (uint16_t) s[i].val;
    }
}

void genRandomByteString(unsigned char *t, int n)
{
    int i, j;
    for (i = 0; i < n; ) {
        j = getrandom(t + i, n - i, 0);
        if (j != -1)
             i += j;
    }
}

void genRandomJobName(unsigned char *t, int n)
{
    int i, j;
    char CHARS[] = "0123456789abcdefghijklmnopqrstuv";
    for (i = 0; i < n; ) {
        j = getrandom(t + i, n - i, 0);
        if (j != -1)
             i += j;
    }
    for (i = 0; i < n; i++) {
        t[i] = CHARS[t[i]%32];
    }
}

#define EXCESS 0 // excess to tweak?
// Build an instance of the key recovery problem by linearisation for a variant of the Elisabeth
// family
// an instance directory is filled with
// - a random key
// - a sparse matric A.bin and its transpose tA.bin, in a format that can be handled by cado-nfs/bwc
// - a file tracking the dimension of the problem/size of matrix A
// One long keystream is generated from the all zero IV, every nibble LSB provides one equation to
// build the system
void buildInstance(variant *algo, char *variant_dir, char *instance_dir) {
    int i, j, k, l;
    mzd_t *polynomial_basis;
    mzd_t *perm_basis[24];
    char buffer[1024];
    unsigned char key[256];
    nibble_t nibble, order;
    int_pair pip[4];
    FILE *fp = NULL;
    rci_t dim;
    uint8_t cst;
    uint32_t entries[1 << 18]; // should be enough
    int nc; // number of variables in the linearized system
    int nr; // number of equations to collect
    int idx_nibble, idx_order, idx_w;
    int offset;
    gsl_spmatrix_uchar *tA=NULL, *ctA=NULL;
    int abort = 0;
    ELI_state es;
    //init nibbles
    nibble_order_init(algo->N);
    //for (i = 0; i < algo->N; i++) {
    //    printf("nibbleIdx %d: %d, %d\n", i, nibbleIndex[i][0], nibbleIndex[i][1]);
    //}
    //load basis information
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    dim = polynomial_basis->nrows;
    nc = 1 + dim * nibbles_len;
    nr = nc + EXCESS;
    //write dimensions
    sprintf(buffer, "%s/dim.txt", instance_dir);
    fp = fopen(buffer, "w");
    if (fprintf(fp, "%d %d\n", nr, nc)<0) {
        printf("Error writing matrix dimension, aborting\n");
        abort = 1;
        goto buildInstance_cleanup;
    }
    fclose(fp); fp = NULL;
    for (i = 0; i < 24; i++) {
        perm_basis[i] = NULL;
    }
    for (i = 0; i < 24; i++) {
        sprintf(buffer, "%s/anf-perm-%02d.png", variant_dir, i);
        perm_basis[i] = mzd_from_png(buffer, 0);
    }
    //generate key and save key
    genRandomByteString(key, algo->N);
    for (i = 0; i < algo->N; i++) key[i] = key[i] % algo->n;
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", key[i]);
    printf("\n");
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "wb");
    if (fwrite(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error writing key file, aborting\n");
        abort = 1;
        goto buildInstance_cleanup;
    }
    fclose(fp); fp = NULL;
    // Alloc spmatrix
    printf("%d %d\n", nc, nr);
    tA = gsl_spmatrix_uchar_alloc_nzmax(nr, nc, nr*(1+algo->T*dim), GSL_SPMATRIX_COO);
    //open instance file
    sprintf(buffer, "%s/A.bin", instance_dir);
    fp = fopen(buffer, "wb");
    //Init elisabeth state, use constant IV = 0
    ELISABETH_init(&es, algo, key, IV);
    //keystream generation
    for (i = 0; i < nr; i++) {
        //prepare to register the equation
        // init number of entries in equation
        entries[0] = 0;
        // init the constant term, this term accumulates:
        // - the keystream bit
        // - the mask values of the nibbles added linearly, without going through h.
        // the constant terms in the anf of h appear in nibble specific variables.
        cst = (ELISABETH_next(&es) & 1);
        //for every component
        for (j = 0; j < algo->T; j++) {
            // add the mask of the affine contribution to the constant term
            cst ^= (es.w[es.perm[5*j+4]]) & 1;
            // compute ANF
            // first decompose info in perm into set selection and order
            // for example [7 2 4 9] nibble: [2 4 7 9] order [1 2 0 3]
            for (k = 0; k < 4; k++) {
                pip[k].idx = k;
                pip[k].val = es.perm[5*j+k];
            }
            qsort(pip, 4, sizeof(int_pair), &cmp_int_pair);
            int_pair_extract_idx_nibble(&order, pip);
            int_pair_extract_val_nibble(&nibble, pip);
            // get the nibble and order index
            idx_nibble = binary_search(&nibble, nibbles, nibbles_len, sizeof(nibble_t), &cmp_nibble);
            idx_order = binary_search(&order, permutations, 24, sizeof(nibble_t), &cmp_nibble);
            /*
            printf("nibble ");
            for (k = 0; k < 5; k++) printf(" %d", perm[5*j+k]);
            printf("\nset ");
            print_nibble(nibbles + idx_nibble);
            printf("\norder ");
            print_nibble(permutations + idx_order);
            printf("\n");
            */
            // get the mask index
            for (idx_w = 0, k = 0; k < 4; k++)
                idx_w = idx_w << algo->s | es.w[es.perm[5*j+k]];

            // linear term
            // we use a property of the polynomialBasis: for a nibble set
            // [n_0, n_1, n_2, n_3], the lsb of nibble n_l appears in position
            // 1 + algo->s*(3-l) of the polynomial basis
            entries[++entries[0]] = 2 + dim*nibbleIndex[es.perm[5*j+4]][0] + algo->s*(3-nibbleIndex[es.perm[5*j+4]][1]);
            gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
            // nibble quartet related monomials
            offset = 1 + dim*idx_nibble;
            for (k = 0; k < dim; k++) {
                if (mzd_read_bit(perm_basis[idx_order], idx_w, k) == 1) {
                    entries[++entries[0]] = offset + k;
                    gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
                }
            }
        }
        // constant term
        if (cst == 1) {
            entries[++entries[0]] = 0;
            gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
        }
        // write row to output file
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            printf("Error writing instance file, aborting\n");
            abort = 1;
            goto buildInstance_cleanup;
        }
    }
    //close instance file
    fclose(fp); fp = NULL;
    // make tA readable row by row
    ctA = gsl_spmatrix_uchar_compress(tA, GSL_SPMATRIX_CSR);
    // write tA to file using cado binary format
    printf("Writing transpose matrix\n");
    sprintf(buffer, "%s/tA.bin", instance_dir);
    fp = fopen(buffer, "wb");
    for (i = 0; i < nc; i++) {
        entries[0] = 0;
        for (l = ctA->p[i]; l < ctA->p[i+1]; l++) {
            entries[++entries[0]] = ctA->i[l];
        }
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            printf("Error writing instance file, aborting\n");
            abort = 1;
            goto buildInstance_cleanup;
        }
    }
    printf("done\n");
    fclose(fp); fp = NULL;
buildInstance_cleanup:
    if (fp) fclose(fp);
    // cleanup nibbles
    nibble_order_free();
    //clean basis information
    for (i = 0; i < 24; i++) {
        if (perm_basis[i])
            mzd_free(perm_basis[i]);
    }
    if (tA) gsl_spmatrix_uchar_free(tA);
    if (ctA) gsl_spmatrix_uchar_free(ctA);
    if (abort) exit(2);
}

// Build an instance of the key recovery problem by linearisation for a variant of the Elisabeth
// family, applying the filtering optimization
// an instance directory is filled with
// - a random key
// - a sparse matrix A.bin and its transpose tA.bin, in a format that can be handled by cado-nfs/bwc
// - a file tracking the dimension of the problem/size of matrix A
// Random IVs are considered, the first generated nibble LSB provides an equation if it only
// involves key nibbles of indexes i < Np
void buildInstanceWithFiltering(variant *algo, char *variant_dir, char *instance_dir, int Np) {
    int i, j, k, l;
    mzd_t *polynomial_basis;
    mzd_t *perm_basis[24];
    char buffer[1024];
    unsigned char key[256], iv[16];
    unsigned char *ivs = NULL;
    int nivs;
    unsigned char *pivs = NULL;
    int npivs;
    int cnt;
    int filter_ok;
    nibble_t nibble, order;
    int_pair pip[4];
    FILE *fp = NULL;
    rci_t dim;
    uint8_t cst;
    uint32_t entries[1 << 18]; // should be enough
    int nc; // number of variables in the linearized system
    int nr; // number of equations to collect
    int idx_nibble, idx_order, idx_w;
    int offset;
    gsl_spmatrix_uchar *tA=NULL, *ctA=NULL;
    int abort = 0;
    ELI_state es;
    //init nibbles
    nibble_order_init(Np);
    //for (i = 0; i < algo->N; i++) {
    //    printf("nibbleIdx %d: %d, %d\n", i, nibbleIndex[i][0], nibbleIndex[i][1]);
    //}
    //load basis information
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    dim = polynomial_basis->nrows;
    //number of variables in the linearized system
    //cst term + LSB of key nibbles i>=Np + polynomials in key nibble bits i < Np
    printf("info %d %d %d %ld\n", algo->N, Np, dim, nibbles_len);
    nc = 1 + (algo->N - Np) + dim * nibbles_len;
    nr = nc + EXCESS;
    //write dimensions
    sprintf(buffer, "%s/dim.txt", instance_dir);
    fp = fopen(buffer, "w");
    if (fprintf(fp, "%d %d\n", nr, nc)<0) {
        printf("Error writing matrix dimension, aborting\n");
        abort = 1;
        goto buildInstanceWithFiltering_cleanup;
    }
    fclose(fp); fp = NULL;
    for (i = 0; i < 24; i++) {
        perm_basis[i] = NULL;
    }
    for (i = 0; i < 24; i++) {
        sprintf(buffer, "%s/anf-perm-%02d.png", variant_dir, i);
        perm_basis[i] = mzd_from_png(buffer, 0);
    }
    //generate key and save key
    genRandomByteString(key, algo->N);
    for (i = 0; i < algo->N; i++) key[i] = key[i] % algo->n;
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", key[i]);
    printf("\n");
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "wb");
    if (fwrite(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error writing key file, aborting\n");
        abort = 1;
        goto buildInstanceWithFiltering_cleanup;
    }
    fclose(fp); fp = NULL;
    // Generate IVs
    ivs = (unsigned char *) malloc((1 << 24) * sizeof(unsigned char));
    nivs = 0;
    cnt = 0;
#pragma omp parallel private(pivs, npivs, j, k, filter_ok, es, iv) \
//                     shared(ivs, nivs, nr, cnt, Np)
{
    pivs = (unsigned char *) malloc((1 << 24) * sizeof(unsigned char));
    npivs = 0;
    #pragma omp for schedule(dynamic)
    for (i = 0; i < nr; i++) {
        do {
            //if (niv % 1000000 == 0) printf("%f, %d/%d\n", log(niv), i, nr);
            //init Elisabeth from iv, to generate the first nibble of the sequence
            genRandomByteString(iv, 16);
            ELISABETH_init(&es, algo, key, iv);
            ELISABETH_next(&es);
            //filtering, for the time being, simple but could be generalized
            filter_ok = 1;
            for (j = 0; filter_ok && j < algo->T; j++) {
                for (k = 0; filter_ok && k < 4; k++) {
                    if (es.perm[5*j+k] >= Np)
                        filter_ok = 0;
                }
            }
        } while (!filter_ok);
        memcpy(pivs + 16*npivs, iv, 16);
        npivs += 1;
        #pragma omp atomic
        cnt++;
        if ((cnt % 10) == 0) printf("%d\n", cnt);
    }
    #pragma omp critical
    {
        memcpy(ivs + 16*nivs, pivs, 16*npivs);
        nivs += npivs;
    }
    free(pivs);
}
    // Generate keystream and system from IVs
    // Alloc spmatrix
    tA = gsl_spmatrix_uchar_alloc(nc, nr);
    //open instance file
    sprintf(buffer, "%s/A.bin", instance_dir);
    fp = fopen(buffer, "wb");
    for (i = 0; i < nr; i++) {
        ELISABETH_init(&es, algo, key, ivs + 16*i);
        //prepare to register the equation
        // init number of entries in equation
        entries[0] = 0;
        // init the constant term, this term accumulates:
        // - the keystream bit
        // - the mask values of the nibbles added linearly, without going through h.
        // the constant terms in the anf of h appear in nibble specific variables.
        cst = (ELISABETH_next(&es) & 1);
        //for every component compute output LSB
        for (j = 0; j < algo->T; j++) {
            // add mask of affine contribution
            cst ^= (es.w[es.perm[5*j+4]]) & 1;
            // compute ANF
            // first decompose info in perm into set selection and order
            // for example [7 2 4 9] nibble: [2 4 7 9] order [1 2 0 3]
            for (k = 0; k < 4; k++) {
                pip[k].idx = k;
                pip[k].val = es.perm[5*j+k];
            }
            qsort(pip, 4, sizeof(int_pair), &cmp_int_pair);
            int_pair_extract_idx_nibble(&order, pip);
            int_pair_extract_val_nibble(&nibble, pip);
            // get the nibble and order index
            idx_nibble = binary_search(&nibble, nibbles, nibbles_len, sizeof(nibble_t), &cmp_nibble);
            idx_order = binary_search(&order, permutations, 24, sizeof(nibble_t), &cmp_nibble);
            /*
            printf("nibble ");
            for (k = 0; k < 5; k++) printf(" %d", perm[5*j+k]);
            printf("\nset ");
            print_nibble(nibbles + idx_nibble);
            printf("\norder ");
            print_nibble(permutations + idx_order);
            printf("\n");
            */
            // get the mask index
            for (idx_w = 0, k = 0; k < 4; k++)
                idx_w = idx_w << algo->s | es.w[es.perm[5*j+k]];

            // linear term
            // case of a nibble >= Np
            if (es.perm[5*j+4] >= Np)
                entries[++entries[0]] = 1 + (es.perm[5*j+4] - Np);
            // case of a nibble < Np, insert the contribution in a nibble system
            else
                entries[++entries[0]] = 2 + (algo->N - Np) + dim*nibbleIndex[es.perm[5*j+4]][0] + algo->s*(3-nibbleIndex[es.perm[5*j+4]][1]);
            gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
            // nibble quartet related monomials
            offset = 1 + (algo->N-Np) + dim*idx_nibble;
            for (k = 0; k < dim; k++) {
                if (mzd_read_bit(perm_basis[idx_order], idx_w, k) == 1) {
                    entries[++entries[0]] = offset + k;
                    gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
                }
            }
        }
        // constant term
        if (cst == 1) {
            entries[++entries[0]] = 0;
            gsl_spmatrix_uchar_set(tA, entries[entries[0]], i, 1);
        }
        // write row to output file
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            printf("Error writing instance file, aborting\n");
            abort = 1;
            goto buildInstanceWithFiltering_cleanup;
        }
    }
    //close instance file
    fclose(fp); fp = NULL;
    // make tA readable row by row
    ctA = gsl_spmatrix_uchar_compress(tA, GSL_SPMATRIX_CSR);
    // write tA to file using cado binary format
    printf("Writing transpose matrix\n");
    sprintf(buffer, "%s/tA.bin", instance_dir);
    fp = fopen(buffer, "wb");
    for (i = 0; i < nc; i++) {
        entries[0] = 0;
        for (l = ctA->p[i]; l < ctA->p[i+1]; l++) {
            entries[++entries[0]] = ctA->i[l];
        }
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            printf("Error writing instance file, aborting\n");
            abort = 1;
            goto buildInstanceWithFiltering_cleanup;
        }
    }
    printf("done\n");
    fclose(fp); fp = NULL;

buildInstanceWithFiltering_cleanup:
    if (fp) fclose(fp);
    // cleanup nibbles
    nibble_order_free();
    //clean basis information
    for (i = 0; i < 24; i++) {
        if (perm_basis[i])
            mzd_free(perm_basis[i]);
    }
    if (tA) gsl_spmatrix_uchar_free(tA);
    if (ctA) gsl_spmatrix_uchar_free(ctA);
    if (ivs) free(ivs);
    if (abort) exit(2);
}

// Inits an instance of the key recovery problem by linearisation
// the instance directory must have been initialized with buildInstanceInit and contains a random key
// Generates a random key in the instance directory
void buildInstanceInit(variant *algo, char *instance_dir) {
    int i;
    char buffer[1024];
    unsigned char key[256];
    FILE *fp = NULL;
    int abort = 0;
    //generate key and save key
    genRandomByteString(key, algo->N);
    for (i = 0; i < algo->N; i++)
        key[i] = key[i] % algo->n;
    printf("KEY ");
    for (i = 0; i < algo->N; i++)
        printf("%X", key[i]);
    printf("\n");
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "wb");
    if (fwrite(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error writing key file, aborting\n");
        abort = 1;
        goto bii_cleanup;
    }

bii_cleanup:
    if (fp) fclose(fp);
    if (abort) exit(2);
}

// Build an instance of the key recovery problem by linearisation for a variant of the Elisabeth
// family, applying the filtering optimization
// the instance directory must have been initialized with buildInstanceInit and contains a random key
// Generates
// - a sparse matrix A.bin and its transpose tA.bin, in a format that can be handled by cado-nfs/bwc
// - a file tracking Na, Nb and the dimension of the problem/size of matrix A
// Random IVs are considered, the first generated nibble LSB provides an equation if it only
// involves key nibbles of indexes Na <= i < Nb
void buildInstanceNext(variant *algo, char *variant_dir, char *instance_dir, int Na, int Nb) {
    mzd_t *polynomial_basis;
    mzd_t *perm_basis[24];
    char buffer[1024];
    unsigned char jobName[13];
    unsigned char key[256], iv[16];
    int cnt, lcnt;
    int filter_ok;
    nibble_t nibble, order;
    int_pair pip[4];
    int i, j, k;
    FILE *fp = NULL;
    rci_t dim;
    uint8_t cst;
    uint32_t *entries;
    int nc; // number of variables in the linearized system
    int nr; // number of equations to collect
    int idx_nibble, idx_order, idx_w;
    int offset;
    int abort = 0;
    ELI_state es;
    //init nibbles
    int Np = Nb - Na;
    nibble_order_init(Np);
    // read key
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "rb");
    if (!fp) {
        fprintf(stderr, "ERROR: %s does not exist\n", buffer);
        exit(1);
    }
    if (fread(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error reading key, aborting\n");
        abort = 1;
        goto bin_cleanup;
    }
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", key[i]);
    printf("\n");
    // generate job name
    genRandomJobName(jobName, sizeof(jobName)-1);
    jobName[sizeof(jobName)-1] = '\0';
    //load basis information
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    dim = polynomial_basis->nrows;
    //number of variables in the linearized system
    //cst term + LSB of key nibbles i < Na or i >= Nb + polynomials in key nibble bits Na <= i < Nb
    nc = 1 + (algo->N - Np) + dim * nibbles_len;
    nr = nc + EXCESS;
    //write dimensions in instance directory
    sprintf(buffer, "%s/%s-dim.txt", instance_dir, jobName);
    fp = fopen(buffer, "w");
    if (fprintf(fp, "%d %d %d %d %d\n", Na, Nb, nr, nc, nr*(1+algo->T*(1+dim))) < 0) {
        printf("Error writing matrix dimension, aborting\n");
        abort = 1;
        goto bin_cleanup;
    }
    fclose(fp);
    fp = NULL;
    // print useful information
    printf("Job %s [%d:%d] matrix size %d\n", jobName, Na, Nb, 4*nr*algo->T*dim);
    fflush(stdout);
    // load bases
    for (i = 0; i < 24; i++) {
        perm_basis[i] = NULL;
    }
    for (i = 0; i < 24; i++) {
        sprintf(buffer, "%s/anf-perm-%02d.png", variant_dir, i);
        perm_basis[i] = mzd_from_png(buffer, 0);
    }
    // Generate keystream and system
    cnt = 0;
    abort = 0;
#pragma omp parallel private(fp, cst, i, j, k, filter_ok, es, iv, buffer, pip, order, nibble, idx_nibble, idx_order, idx_w, entries, offset, lcnt) \
//                     shared(instance_dir, jobName, algo, nr, cnt, Na, Nb, nibbles, permutations, abort)
{
    entries = NULL;
    //open instance file
    sprintf(buffer, "%s/%s-A-%d.bin", instance_dir, jobName, omp_get_thread_num());
    fp = fopen(buffer, "wb");
    if (!fp) {
        printf("problem opening file, aborting\n");
        abort = 1;
    }
    //alloc entries
    entries = (uint32_t *) malloc((1 << 18)*sizeof(uint32_t));
    if (!entries) {
        printf("problem allocating entries array, aborting\n");
        abort = 1;
    }
    lcnt = 0;
    #pragma omp for schedule(dynamic)
    for (i = 0; i < nr; i++) {
        if (abort) continue;
        // Generate an appropriate IV
        do {
            //init Elisabeth from iv, to generate the first nibble of the sequence
            genRandomByteString(iv, 16);
            ELISABETH_init(&es, algo, key, iv);
            cst = ELISABETH_next(&es) & 1;
            //filtering
            filter_ok = 1;
            for (j = 0; filter_ok && j < algo->T; j++) {
                for (k = 0; filter_ok && k < 4; k++) {
                    if (es.perm[5*j+k] >= Nb || es.perm[5*j+k] < Na)
                        filter_ok = 0;
                }
            }
        } while (!filter_ok);
        //prepare to register the equation
        // init number of entries in equation
        entries[0] = 0;
        // init the constant term, this term accumulates:
        // - the keystream bit
        // - the mask values of the nibbles added linearly, without going through h.
        // the constant terms in the anf of h appear in nibble specific variables.
        //for every component compute output LSB
        for (j = 0; j < algo->T; j++) {
            // add mask of affine contribution
            cst ^= (es.w[es.perm[5*j+4]]) & 1;
            // compute ANF
            // first decompose info in perm into set selection and order
            // for example [7 2 4 9] nibble: [2 4 7 9] order [1 2 0 3]
            // to account for filtering, we shift the perm values by Na
            for (k = 0; k < 4; k++) {
                pip[k].idx = k;
                pip[k].val = es.perm[5*j+k] - Na;
            }
            qsort(pip, 4, sizeof(int_pair), &cmp_int_pair);
            int_pair_extract_idx_nibble(&order, pip);
            int_pair_extract_val_nibble(&nibble, pip);
            // get the nibble and order index
            idx_nibble = binary_search(&nibble, nibbles, nibbles_len, sizeof(nibble_t), &cmp_nibble);
            idx_order = binary_search(&order, permutations, 24, sizeof(nibble_t), &cmp_nibble);
            /*
            printf("nibble ");
            for (k = 0; k < 5; k++) printf(" %d", perm[5*j+k]);
            printf("\nset ");
            print_nibble(nibbles + idx_nibble);
            printf("\norder ");
            print_nibble(permutations + idx_order);
            printf("\n");
            */
            // get the mask index
            for (idx_w = 0, k = 0; k < 4; k++)
                idx_w = idx_w << algo->s | es.w[es.perm[5*j+k]];
            // linear term
            // case of a nibble < Na
            if (es.perm[5*j+4] < Na)
                entries[++entries[0]] = 1 + (es.perm[5*j+4]);
            // case of a nibble >= Nb
            else if (es.perm[5*j+4] >= Nb)
                entries[++entries[0]] = 1 + (Na + es.perm[5*j+4] - Nb);
            // case of a nibble in [Na:Nb], insert the contribution in a nibble system
            else
                entries[++entries[0]] = 2 + (algo->N - Np) + dim*nibbleIndex[es.perm[5*j+4]-Na][0] + algo->s*(3-nibbleIndex[es.perm[5*j+4]-Na][1]);
            // nibble quartet related monomials
            offset = 1 + (algo->N-Np) + dim*idx_nibble;
            for (k = 0; k < dim; k++) {
                if (mzd_read_bit(perm_basis[idx_order], idx_w, k) == 1) {
                    entries[++entries[0]] = offset + k;
                }
            }
        }
        // constant term
        if (cst == 1) {
            entries[++entries[0]] = 0;
        }
        // write row to output file
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            fprintf(stderr, "Error writing instance file, aborting\n");
            abort = 1;
        }
        lcnt++;
        if (lcnt % 500 == 0)
        {
            #pragma omp critical
            {
            cnt += lcnt;
            lcnt = 0;
            fprintf(stderr, "Progress: %d/%d\r", cnt, nr);
            fflush(stderr);
            }
        }
    }
    //close instance file
    fclose(fp); fp = NULL;
    if (entries) {
        free(entries);
        entries = NULL;
    }
}

bin_cleanup:
    if (fp) fclose(fp);
    // cleanup nibbles
    nibble_order_free();
    //clean basis information
    for (i = 0; i < 24; i++) {
        if (perm_basis[i])
            mzd_free(perm_basis[i]);
    }
    if (abort) exit(2);
}

//Finalize the creation of an instance
//Essentially performs the transposition of <jobName>-A.bin
void buildInstanceFinalize(variant *algo, char *variant_dir, char *instance_dir, char *jobname) {
    int Na, Nb, nr, nc, nzmax, i, j, k, l, nentry, abort = 0;
    gsl_spmatrix_uchar *tA=NULL, *ctA=NULL;
    char buffer[1024];
    FILE *fp = NULL;
    uint32_t entries[1 << 18]; // should be large enough
    // read dimensions and key nibble subset target
    sprintf(buffer, "%s/%s-dim.txt", instance_dir, jobname);
    fp = fopen(buffer, "r");
    if (fscanf(fp, "%d %d %d %d %d\n", &Na, &Nb, &nr, &nc, &nzmax) != 5) {
        printf("Problem reading dimensions for %s, aborting\n", jobname);
        abort = 1;
        goto bif_cleanup;
    }
    fclose(fp); fp = NULL;

    // Alloc spmatrix
    tA = gsl_spmatrix_uchar_alloc_nzmax(nc, nr, nzmax, GSL_SPMATRIX_COO);
    // read A matrix and fill tA matrix from A
    printf("Reading matrix\n");
    sprintf(buffer, "%s/%s-A.bin", instance_dir, jobname);
    fp = fopen(buffer, "rb");
    nentry = 0; // number of entries left to read in equation j
    j = -1; //equation number
    while(!feof(fp)) {
        if (fread(&k, sizeof(uint32_t), 1, fp) != 1) {
            if (feof(fp)) continue;
            printf("Problem reading next entry, aborting\n");
            abort = 1;
            goto bif_cleanup;
        }
        if (nentry == 0) {
            // Start handling next row
            nentry = k;
            j++;
            continue;
        }
        gsl_spmatrix_uchar_set(tA, k, j, 1);
        nentry--;
    }
    fclose(fp); fp = NULL;
    // make tA readable row by row
    ctA = gsl_spmatrix_uchar_compress(tA, GSL_SPMATRIX_CSR);
    // write tA to file using cado binary format
    printf("Writing transpose matrix\n");
    sprintf(buffer, "%s/%s-tA.bin", instance_dir, jobname);
    fp = fopen(buffer, "wb");
    for (i = 0; i < nc; i++) {
        entries[0] = 0;
        for (l = ctA->p[i]; l < ctA->p[i+1]; l++) {
            entries[++entries[0]] = ctA->i[l];
        }
        if (fwrite(entries, sizeof(uint32_t), entries[0]+1, fp) != entries[0]+1) {
            printf("Error writing instance file, aborting\n");
            abort = 1;
            goto bif_cleanup;
        }
    }
bif_cleanup:
    if (fp)
        fclose(fp);
    if (tA) gsl_spmatrix_uchar_free(tA);
    if (ctA) gsl_spmatrix_uchar_free(ctA);
    if (abort)
        exit(2);
}

// Checks an intance of the problem
// - read the key
// - read the polynomial basis matrix
// - build the extended key, ie evaluate the polynomial basis matrix on the key bits
// - read the system
// - check the extended key is in the kernel of the system matrix
void checkInstance(variant *algo, char *variant_dir, char *instance_dir) {
    unsigned char key[256];
    char buffer[1024];
    int i, j, K, b;
    uint32_t k;
    int dim;
    int N = 1 << (algo->s*4);
    int L;
    FILE *fp;
    int nentry, sum;
    int abort = 0;
    nibble_t lkey;
    mzd_t *polynomial_basis = NULL, *monomial_key = NULL, *tmp = NULL, *tmpp = NULL, *win;
    nibble_order_init(algo->N);
    monomial_order_init(algo->s*4);
    // read key
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "rb");
    if (fread(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error reading key, aborting\n");
        abort = 1;
        goto cleanup;
    }
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", key[i]);
    printf("\n");
    // read polynomial basis
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    // allocate tmp vectors
    dim = polynomial_basis->nrows;
    L = 1 + dim * nibbles_len;
    printf("Number of variables: %d\n", L);
    monomial_key = mzd_init(L, 1);
    tmp = mzd_init(N, 1);
    tmpp = mzd_init(dim, 1);
    // build derived monomial vector
    // set beginning of monomial key
    mzd_write_bit(monomial_key, 0, 0, 1);
    // for every nibble set
    for (i = 0; i < nibbles_len; i++) {
        // extract the key nibbles
        for (j = 0, K = 0; j < 4; j++) {
            lkey[j] = key[nibbles[i][j]];
            K = (K << algo->s) | lkey[j];
        }
        // form the monomial vector
        for (j = 0; j < N; j++)
            mzd_write_bit(tmp, j, 0, (j & K) == j ? 1 : 0);
        // reoder monomials
        mzd_apply_p_left(tmp, P2NMO);
        // project on polynomial basis
        mzd_mul(tmpp, polynomial_basis, tmp, 0);
        // save in monomial key
        win = mzd_init_window (monomial_key, 1 + dim*i, 0, 1 + dim*i+dim, 1);
        mzd_copy(win, tmpp);
        mzd_free_window(win);
    }
    // read instance
    sprintf(buffer, "%s/A.bin", instance_dir);
    fp = fopen(buffer, "rb");
    nentry = 0; // number of entries left to read in equation j
    sum = -1; //current value of equation evaluation, -1 : undefined
    j = -1; //equation number
    while(!feof(fp)) {
        if (fread(&k, sizeof(uint32_t), 1, fp) != 1) {
            if (feof(fp)) continue;
            printf("Problem reading next entry, aborting\n");
            abort = 1;
            goto cleanup;
        }
        if (nentry == 0) {
            // Start handling next equation
            nentry = k;
            j++;
            //printf("Equation %d: %d entries\n", j, nentry);
            sum = 0;
            continue;
        }
        b = mzd_read_bit(monomial_key, k, 0);
        sum ^= b;
        //printf("Equation %d: %d %d\n", j, k, b);
        nentry--;
        // Finish handling equation j
        if (nentry == 0) {
            // check that the monomial vector is in the (right) kernel of the matrix
            if (sum != -1)
                if (sum == 1)
                    printf("Check Equation %d: %s\n", j, "KO");
                //printf("Check Equation %d: %s\n", j, sum == 0 ? "OK" : "KO");
        }
    }
    printf("Checked %d equations\n", j);
cleanup:
    nibble_order_free();
    monomial_order_free();
    if (tmp) mzd_free(tmp);
    if (tmpp) mzd_free(tmpp);
    if (polynomial_basis) mzd_free(polynomial_basis);
    mzd_free(monomial_key);
    if (abort) exit(2);
}


// Checks an intance of the problem with filtering
// - read the key
// - read the polynomial basis matrix
// - build the extended key, ie evaluate the polynomial basis matrix on the key bits
// - read the system
// - check the extended key is in the kernel of the system matrix
void checkInstanceWithFiltering(variant *algo, char *variant_dir, char *instance_dir, int Np) {
    unsigned char key[256];
    char buffer[1024];
    int i, j, K, b;
    uint32_t k;
    int dim;
    int N = 1 << (algo->s*4);
    int L;
    FILE *fp;
    int nentry, sum;
    int abort = 0;
    nibble_t lkey;
    mzd_t *polynomial_basis = NULL, *monomial_key = NULL, *tmp = NULL, *tmpp = NULL, *win;
    nibble_order_init(Np);
    monomial_order_init(algo->s*4);
    // read key
    sprintf(buffer, "%s/key.dat", instance_dir);
    fp = fopen(buffer, "rb");
    if (fread(key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error reading key, aborting\n");
        abort = 1;
        goto ciwf_cleanup;
    }
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", key[i]);
    printf("\n");
    // read polynomial basis
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    // allocate tmp vectors
    dim = polynomial_basis->nrows;
    L = 1 + (algo->N - Np) + dim * nibbles_len;
    printf("Number of variables: %d\n", L);
    monomial_key = mzd_init(L, 1);
    tmp = mzd_init(N, 1);
    tmpp = mzd_init(dim, 1);
    // build derived monomial vector
    // set beginning of monomial key
    mzd_write_bit(monomial_key, 0, 0, 1);
    for (i = Np; i < algo->N; i++)
        mzd_write_bit(monomial_key, 1 + i-Np, 0, key[i] & 1);
    // for every nibble set
    for (i = 0; i < nibbles_len; i++) {
        // extract the key nibbles
        for (j = 0, K = 0; j < 4; j++) {
            lkey[j] = key[nibbles[i][j]];
            K = (K << algo->s) | lkey[j];
        }
        // form the monomial vector
        for (j = 0; j < N; j++)
            mzd_write_bit(tmp, j, 0, (j & K) == j ? 1 : 0);
        // reoder monomials
        mzd_apply_p_left(tmp, P2NMO);
        // project on polynomial basis
        mzd_mul(tmpp, polynomial_basis, tmp, 0);
        // save in monomial key
        win = mzd_init_window (monomial_key, 1 + (algo->N-Np) + dim*i, 0,
                                             1 + (algo->N-Np) + dim*i+dim, 1);
        mzd_copy(win, tmpp);
        mzd_free_window(win);
    }
    // print the polynomial key
    printf("polynomial key: [");
    for (i = 0; i < L; i++) {
        if (i > 0) printf(", ");
        printf("%x",mzd_read_bit(monomial_key, i, 0));
    }
    printf("]\n");
    // read instance
    sprintf(buffer, "%s/A.bin", instance_dir);
    fp = fopen(buffer, "rb");
    nentry = 0; // number of entries left to read in equation j
    sum = -1; //current value of equation evaluation, -1 : undefined
    j = -1; //equation number
    while(!feof(fp)) {
        if (fread(&k, sizeof(uint32_t), 1, fp) != 1) {
            if (feof(fp)) continue;
            printf("Problem reading next entry, aborting\n");
            abort = 1;
            goto ciwf_cleanup;
        }
        if (nentry == 0) {
            // Start handling next equation
            nentry = k;
            j++;
            //printf("Equation %d: %d entries\n", j, nentry);
            sum = 0;
            continue;
        }
        b = mzd_read_bit(monomial_key, k, 0);
        sum ^= b;
        //printf("Equation %d: %d %d\n", j, k, b);
        nentry--;
        // Finish handling equation j
        if (nentry == 0) {
            // check that the monomial vector is in the (right) kernel of the matrix
            if (sum != -1)
                if (sum == 1)
                    printf("Check Equation %d: %s\n", j, "KO");
                //printf("Check Equation %d: %s\n", j, sum == 0 ? "OK" : "KO");
        }
    }
    printf("Checked %d equations\n", j);
ciwf_cleanup:
    nibble_order_free();
    monomial_order_free();
    if (tmp) mzd_free(tmp);
    if (tmpp) mzd_free(tmpp);
    if (polynomial_basis) mzd_free(polynomial_basis);
    mzd_free(monomial_key);
    if (abort) exit(2);
}

int auxReadInstance(int nr, int nc, FILE *fout, FILE *fin, char *matname)
{
    mzd_t *mat = NULL;
    int nentry;
    int j;
    uint32_t k;
    int abort = 0;

    mat = mzd_init(nr, nc);
    nentry = 0; // number of entries left to read in equation j
    j = -1; //equation number
    // read instance
    while(!feof(fin)) {
        if (fread(&k, sizeof(uint32_t), 1, fin) != 1) {
            if (feof(fin)) continue;
            abort = 1;
            goto aux_cleanup;
        }
        if (nentry == 0) {
            // Start handling next equation
            nentry = k;
            j++;
            continue;
        }
        mzd_write_bit(mat, j, k, 1);
        nentry--;
    }
    mzd_to_png(mat, "glop.png", 0, NULL, 0);
    // print matrix
    /*
    fprintf(fout, "%s = matrix(GF(2), %d, %d, [", matname, mat->nrows, mat->ncols);
    for (i = 0; i < mat->nrows; i++) {
        for (j = 0; j < mat->ncols; j++) {
            if (i > 0 || j > 0) fprintf(fout, ", ");
            fprintf(fout, "%d", mzd_read_bit(mat, i, j));
        }
    }
    fprintf(fout, "])\n");
    */
aux_cleanup:
    if (mat) mzd_free(mat);
    return abort;
}

// read the system associated to an instance of the problem and print it out in Sage format.
void readInstance(variant *algo, char *variant_dir, char *instance_dir)
{
    char buffer[1024];
    int nr, nc;
    int abort = 0;
    FILE *fout = NULL, *fin=NULL;
    // Determine relevant dimensions and alloc matrix
    // read dimensions
    sprintf(buffer, "%s/dim.txt", instance_dir);
    fin = fopen(buffer, "r");
    if(fscanf(fin, "%d %d\n", &nr, &nc) != 2) {
        abort = 1;
        goto readInstance_cleanup;
    }
    fclose(fin); fin = NULL;
    sprintf(buffer, "%s/mat.sage", instance_dir);
    fout = fopen(buffer, "w");
    sprintf(buffer, "%s/A.bin", instance_dir);
    fin = fopen(buffer, "rb");
    if (auxReadInstance(nr, nc, fout, fin, "A")) {
        printf("Problem reading %s, aborting\n", buffer);
        abort = 1;
        goto readInstance_cleanup;
    }
    fclose(fin); fin = NULL;
    /*
    sprintf(buffer, "%s/tA.bin", instance_dir);
    fin = fopen(buffer, "rb");
    if (auxReadInstance(nc, nr, fout, fin, "tA")) {
        printf("Problem reading %s, aborting\n", buffer);
        abort = 1;
        goto readInstance_cleanup;
    }
    fclose(fin); fin = NULL;
    */
readInstance_cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (abort) exit(2);
}

// read the polynomial basis matrix associated to a variant and print out its definition in text,
// in a format readable in Sage
void readPolynomialBasisMatrix(variant *algo, char *variant_dir) {
    char buffer[1024];
    int i, j;
    mzd_t *polynomial_basis = NULL;
    // read polynomial basis
    sprintf(buffer, "%s/basis.png", variant_dir);
    polynomial_basis = mzd_from_png(buffer, 0);
    // print matrix
    printf("B = matrix(GF(2), %d, %d, [", polynomial_basis->nrows, polynomial_basis->ncols);
    for (i = 0; i < polynomial_basis->nrows; i++) {
        for (j = 0; j < polynomial_basis->ncols; j++) {
            if (i > 0 || j > 0) printf(", ");
            printf("%d", mzd_read_bit(polynomial_basis, i, j));
        }
    }
    printf("])\n");
    if (polynomial_basis) mzd_free(polynomial_basis);
}

// reads the solution of an attacked instance. This a file output by cado-nfs/bwc
uint64_t *readSolution(char *instance_dir, int transpose, int *len, int *dim, char *job_name)
{
    FILE *fp = NULL;
    char buffer[1024];
    int i, nr, nc, n, d = 0;
    int Na, Nb, nzmax;
    int abort = 0;
    uint64_t *res = NULL, acc = 0;

    if (job_name != NULL) {
        sprintf(buffer, "%s/%s-dim.txt", instance_dir, job_name);
        fp = fopen(buffer, "r");
        if (fscanf(fp, "%d %d %d %d %d\n", &Na, &Nb, &nr, &nc, &nzmax) != 5) {
            printf("Problem reading dimensions for %s, aborting\n", job_name);
            abort = 1;
            goto readSolution_cleanup;
        }
        fclose(fp); fp = NULL;
    }
    else {
        sprintf(buffer, "%s/dim.txt", instance_dir);
        fp = fopen(buffer, "r");
        if(fscanf(fp, "%d %d\n", &nr, &nc) != 2) {
            abort = 1;
            goto readSolution_cleanup;
        }
        fclose(fp); fp = NULL;
    }
    if (transpose)
        n = nc;
    else
        n = nr;
    if (!(res = (uint64_t *) malloc(n*sizeof(uint64_t)))) {
        abort = 1;
        goto readSolution_cleanup;
    }
    // read the solution space in memory
    if (job_name != NULL) {
        sprintf(buffer, "%s/%s-W", instance_dir, job_name);
    } else {
        sprintf(buffer, "%s/W", instance_dir);
    }
    fp = fopen(buffer, "rb");
    for (i = 0; i < n; i++) {
        if (fread(res + i, sizeof(uint64_t), 1, fp) != 1) {
            abort = 1;
            goto readSolution_cleanup;
        }
        acc |= res[i];
    }
    fclose(fp); fp = NULL;
    // determine the dimension of the solution space
    while (acc) {
        d++;
        acc >>= 1;
    }

readSolution_cleanup:
    if (fp) fclose(fp);
    if (abort) {
        if (res) free(res);
        return NULL;
    }
    else {
        if (len) *len = n;
        if (dim) *dim = d;
        return res;
    }
}

// reads and print out the solution of an attacked instance
void printSolution(char *instance_dir)
{
    int i, j, n;
    uint64_t *sol;
    int dim;

    if (!(sol = readSolution(instance_dir, 0, &n, &dim, NULL))) {
        printf("Problem reading solution, aborting\n");
        goto printSolution_cleanup;
    }
    for (j = 0; j < dim; j++) {
        printf("[");
        for (i = 0; i < n; i++) {
            if (i > 0) printf(", ");
            printf("%ld", (sol[i] >> j) & 1);
        }
        printf("]\n");
    }
printSolution_cleanup:
    if (sol) free(sol);
}

int auxExtractKey(variant *algo, uint8_t *lkey, uint8_t *solVec, mzd_t *M)
{
    int i, j, l;
    int pkey = 0;
    int candidates[16], cur, n = 0;
    //extract the LSBs
    for (i = 0; i < 4; i++) {
        for (j = 0; j < algo->s-1; j++) {
            //bits[(3-i)*algo->s + j] = solVec[1 + i*algo->s + j];
            if (solVec[1 + i*algo->s + j]) // bits[(3-i)*algo->s + j])
                pkey |= (1 << (i*algo->s + j));
        }
    }
    //generate list of MSBs candidates
    for (i = 0; i < 16; i++) {
        candidates[i] = 0;
    }
    for (l = 1, cur = (1 << (algo->s-1)); l < 16; l*=2, cur <<= algo->s) {
        for (i = 0; i < 16; i += 2*l) {
            for (j = 0; j < l; j++) {
                candidates[i+j+l] |= cur;
            }
        }
    }
    //Exhaust the MSBs
    for (i = 0; i < 16; i++) {
        // candidate key (for this nibble)
        cur = pkey ^ candidates[i];
        for (j = 0; j < M->nrows; j++) {
            if (solVec[j] != mzd_read_bit(M, j, cur)) break;
        }
        if (j != M->nrows) continue;
        // candidate found
        for (j = 0; j < 4; j++) {
            lkey[4*n + j] = (cur >> ((3-j)*algo->s)) % (1 << algo->s);
        }
        n++;
    }
    return n;
}

#define MAX_N 64
#define NIBBLE_NOT_SET -1
//enough space to allow for N = 64
#define MAX_NIBBLE_LEN (1<<20)
typedef struct _state_backtracking {
    int nspec; // number of key nibbles specified at this stage
    int spec[4]; // index of key nibbles specified at this stage
    int choice;
} state_backtracking;

void print_state_bt(state_backtracking *st)
{
    int j;
    printf("%d [", st->nspec);
    for (j = 0; j < st->nspec; j++) {
        printf(" %d", st->spec[j]);
    }
    printf("] %d\n", st->choice);
}

// reads and print out the solution of an attacked instance
void extractKey(variant *algo, char *variant_dir, char *instance_dir, char *job_name)
{
    int i, j, n, dim, J;
    int Na, Nb, Np;
    uint64_t *sol = NULL;
    uint8_t *solVec = NULL;
    int *nlkey = NULL;
    uint8_t *lkey = NULL, *lkeycur;
    mzd_t *B = NULL, *M = NULL, *Mtmp = NULL;
    int nr, nc, nzmax;
    char fname[1024];
    FILE *fp;
    unsigned char real_key[256];
    int key[MAX_N];
    state_backtracking *state = NULL;;
    int depth;

    // read dimensions and key nibble subset target
    if (job_name != NULL) {
        sprintf(fname, "%s/%s-dim.txt", instance_dir, job_name);
        fp = fopen(fname, "r");
        if (fscanf(fp, "%d %d %d %d %d\n", &Na, &Nb, &nr, &nc, &nzmax) != 5) {
            printf("Problem reading dimensions for %s, aborting\n", job_name);
            goto extractKey_cleanup;
        }
        Np = Nb - Na;
        fclose(fp); fp = NULL;
    }
    else {
        Np = algo->N;
    }

    nibble_order_init(Np);
    monomial_order_init(algo->s*4);

    // load polynomial basis
    sprintf(fname, "%s/basis.png", variant_dir);
    B = mzd_from_png(fname, 0);

    // read key
    sprintf(fname, "%s/key.dat", instance_dir);
    fp = fopen(fname, "rb");
    if (fread(real_key, sizeof(unsigned char), algo->N, fp) != algo->N) {
        printf("Error reading key, aborting\n");
        goto extractKey_cleanup;
    }
    printf("KEY ");
    for (i = 0; i < algo->N; i++) printf("%X", real_key[i]);
    printf("\n");

    // read solution basis
    if (!(sol = readSolution(instance_dir, 0, &n, &dim, job_name))) {
        printf("Problem reading solution, aborting\n");
        goto extractKey_cleanup;
    }
    if (dim > 10) {
        printf("Solution space dimension too large (2^%d), aborting\n", n);
        goto extractKey_cleanup;
    }
    if (!(solVec = (uint8_t *) malloc(sizeof(uint8_t)*n))) {
        printf("Problem allocating solution vector, aborting\n");
        goto extractKey_cleanup;
    }
    // Allocate space to store the partial solutions
    // hope for less than 4 solutions per nibble on average
    lkey = (uint8_t *) malloc(sizeof(uint8_t) * 4 * 4 * nibbles_len);
    nlkey = (int *) malloc(sizeof(int) * (nibbles_len+1));
    if (!lkey || !nlkey) {
        printf("Problem allocating local key candidates, aborting\n");
        goto extractKey_cleanup;
    }
    // Allocating space for the backtracking stack
    state = (state_backtracking *) malloc(MAX_NIBBLE_LEN * sizeof(state_backtracking));
    if (!state) {
        printf("Problem allocating backtracking stack, aborting\n");
        goto extractKey_cleanup;
    }
    // Precompute polynomial vectors corresponding to key nibbles
    //   Generate monomial matrix
    M = identityMatrix(1 << (4*algo->s));
    applyMobius(M);
    //   Reorder monomials
    mzd_apply_p_left(M, P2NMO);
    // project on the polynomial basis
    Mtmp = mzd_mul(NULL, B, M, 0);
    // Look up for the solution
    for (i = 0; i < (1 << dim); i++) {
        // combine solution vectors determined by the bits of i
        for (j = 0; j < n; j++) {
            solVec[j] = __builtin_parity(i & sol[j]);
        }
        // check the constant term
        if (solVec[0] != 1)
            continue;
        // for all nibbles extract the local solution for the nibble
        nlkey[0] = 0;
        for (j = 0; j < nibbles_len; j++) {
            nlkey[j+1] = nlkey[j] + auxExtractKey(algo, lkey + 4*nlkey[j],
                    solVec + 1 + algo->N-Np + B->nrows*j, Mtmp);
            // no candidate solution found for this nibble, aborting exploration for
            // this value of dim
            if (nlkey[j+1] == nlkey[j])
                break;
        }
        // if no candidate found for one nibble, abort the considered i value
        if (j < nibbles_len)
            continue;
        printf("Candidates found for all nibbles, merging\n");
        // candidates found for all nibbles, merge to get candidates for the whole key
        // by backtracking.
        // setup initial state
        for (j = 0; j < Np; j++) {
            key[j] = NIBBLE_NOT_SET;
        }
        depth = 0;
        state[0].nspec = 0;
        state[0].choice = nlkey[0];
        // backtracking
        while (depth >= 0) {
            // case of a leaf, print out the key
            if (depth == nibbles_len) {
                printf("SOL ");
                for (j = 0; j < algo->N; j++)
                    if (j < Na || j >= Nb)
                        printf("*");
                    else
                        printf("%d", key[j-Na]);
                printf("\n");
            }
            // case of a leaf or a node with all children have been explored, backtrack
            if (depth == nibbles_len || state[depth].choice >= nlkey[depth+1]) {
                for (j = 0; j < state[depth].nspec; j++) {
                    J = state[depth].spec[j];
                    key[nibbles[depth-1][J]] = NIBBLE_NOT_SET;
                }
                depth--;
                continue;
            }
            // consider the next children choice
            lkeycur = lkey + 4*state[depth].choice;
            state[depth+1].nspec = 0;
            for (j = 0; j < 4; j++) {
                if (key[nibbles[depth][j]] == NIBBLE_NOT_SET) {
                    state[depth+1].spec[state[depth+1].nspec++] = j;
                } else if (key[nibbles[depth][j]] != lkeycur[j]) {
                    break;
                }
            }
            // remember that this children choice has been analyzed
            state[depth].choice++;
            // if the choice is not consistent, go to next choice
            if (j < 4)
                continue;
            // Setup the consistent choice selection and iterate
            for (j = 0; j < state[depth+1].nspec; j++) {
                J = state[depth+1].spec[j];
                key[nibbles[depth][J]] = lkeycur[J];
            }
            state[depth+1].choice = nlkey[depth+1];
            depth++;
        }
    }

extractKey_cleanup:
    nibble_order_free();
    monomial_order_free();
    if (sol) free(sol);
    if (B) mzd_free(B);
    if (M) mzd_free(M);
    if (Mtmp) mzd_free(Mtmp);
    if (lkey) free(lkey);
    if (nlkey) free(nlkey);
    if (state) free(state);
}

// Checks the solution of an intance of the problem with filtering
// - read the solution vectors
// - read the system
// - check the solution vectors statisfy the system
void checkSolutionInstanceWithFiltering(variant *algo, char *instance_dir) {
    char buffer[1024];
    int i, j, b;
    uint32_t k;
    uint64_t *sol=NULL;
    int n, dim;
    FILE *fp = NULL;
    int nentry, sum;
    int abort = 0;
    // read solution
    if (!(sol = readSolution(instance_dir, 0, &n, &dim, NULL))) {
        printf("Problem reading solution, aborting\n");
        abort = 1;
        goto csiwf_cleanup;
    }
    for (i = 0; i < dim; i++) {
        // read instance
        sprintf(buffer, "%s/A.bin", instance_dir);
        fp = fopen(buffer, "rb");
        nentry = 0; // number of entries left to read in equation j
        sum = -1; //current value of equation evaluation, -1 : undefined
        j = -1; //equation number
        while(!feof(fp)) {
            if (fread(&k, sizeof(uint32_t), 1, fp) != 1) {
                if (feof(fp)) continue;
                printf("Problem reading next entry, aborting\n");
                abort = 1;
                goto csiwf_cleanup;
            }
            if (nentry == 0) {
                // Start handling next equation
                nentry = k;
                j++;
                //printf("Equation %d: %d entries\n", j, nentry);
                sum = 0;
                continue;
            }
            b = (sol[k] >> i) & 1;
            sum ^= b;
            //printf("Equation %d: %d %d\n", j, k, b);
            nentry--;
            // Finish handling equation j
            if (nentry == 0) {
                // check that the vector is in the (right) kernel of the matrix
                if (sum != -1)
                    if (sum == 1)
                        printf("Check Equation %d: %s\n", j, "KO");
                    //printf("Check Equation %d: %s\n", j, sum == 0 ? "OK" : "KO");
            }
        }
        fclose(fp);
        fp = NULL;
        printf("Checked %d equations\n", j);
    }
csiwf_cleanup:
    if (sol) free(sol);
    if (fp) fclose(fp);
    if (abort) exit(2);
}

void usage()
{
    printf("Usage:\n");
    printf("  * keystream: generate keystream from a test key \n");
    printf("  * buildPolynomialBasisMatrix: build the polynomial basis matrix for the active variant\n");
    printf("  * buildBasisMatrices: build the basis matrices of functions h\n");
    printf("  * buildInstance: generate key and build an instance of a linearized system (without filtering)\n");
    printf("  * checkInstance: check the consistency of the key and the sytem of an instance\n");
    printf("  * buildInstanceInit: generate key of an instance with filtering\n");
    printf("  * buildInstanceNext: generate system of an instance with filtering\n");
    printf("  * buildInstanceFinalize: transposes a system of an instance with filtering\n");
    printf("  * extractKey: extract the elisabeth key from the BW solution space W to a linearized system\n");

/* TODO: advertize intermediate functions ?
    printf("  * genGMatrix: TODO\n");
    printf("  * genHMatrix: TODO\n");
    printf("  * genHMatrixTxt: TODO\n");
    printf("  * testMobius: TODO\n");
    printf("  * gMatrixRank: TODO\n");
    printf("  * buildBasisHMatrix: TODO\n");
    printf("  * testBasisMatrices: TODO\n");
    printf("  * reorderMonomials: TODO\n");
    printf("  * inspectOrderedBasis: TODO\n");
    printf("  * testMonomialOrder: TODO\n");
    printf("  * testAltMonomialOrder: TODO\n");
    printf("  * testAltMonomialReorder: TODO\n");
    printf("  * testImplem: TODO\n");
    printf("  * testNibbleOrder: TODO\n");
    printf("  * readInstance: TODO\n");
    printf("  * readPolynomialBasisMatrix: TODO\n");
    printf("  * printSolution: TODO\n");
*/
}

int main(int argc, char **argv)
{

    if (argc == 1) {
        usage();
        exit(EXIT_SUCCESS);
    }

    if (!strcmp(argv[1], "genGMatrix")) {
        mzd_t *A = constructMatrix(&Elisabeth4, NULL);
        mzd_to_png(A, "A_rref.png", 0, NULL, 0);
        mzd_free(A);

    }

    else if (!strcmp(argv[1], "genHMatrix")) {
        int i, j;
        mzd_t *A = constructHMatrix(&Elisabeth4);
        char fname[256];
        // write TT in png
        sprintf(fname, "%s_TT.png", argv[2]);
        mzd_to_png(A, fname, 0, NULL, 0);
        // write TT in txt
        sprintf(fname, "%s_TT.txt", argv[2]);
        FILE *fp = fopen(fname, "w");
        fprintf(fp, "%u %u\n", A->nrows, A->ncols);
        for (i = 0; i < A->nrows; i++) {
            for (j = 0; j < A->ncols; j++) {
                fprintf(fp, " %d", mzd_read_bit(A, i, j));
            }
            fprintf(fp, "\n");
        }
        fclose(fp);
        // compute rank
        size_t rank = (size_t)mzd_echelonize(A, 0);
        printf("rank = %ld\n", rank);
        mzd_free(A);
    }

    else if (!strcmp(argv[1], "genHMatrixTxt")) {
        mzd_t *A = constructHMatrix(&Elisabeth4);
        FILE *fp = fopen("A_H.txt", "w");
        int i, j;
        fprintf(fp, "%u %u\n", A->nrows, A->ncols);
        for (i = 0; i < A->nrows; i++) {
            for (j = 0; j < A->ncols; j++) {
                fprintf(fp, " %d", mzd_read_bit(A, i, j));
            }
            fprintf(fp, "\n");
        }
        fclose(fp);
        mzd_free(A);
    }

    else if (!strcmp(argv[1], "testMobius")) {
        mzd_t *A = identityMatrix(32);
        applyMobius(A);
        mzd_to_png(A, "A_mobius.png", 0, NULL, 0);
        mzd_free(A);
    }

    else if (!strcmp(argv[1], "gMatrixRank")) {
        mzd_t *A = mzd_from_png(argv[2], 0);
        size_t rank = (size_t)mzd_echelonize(A, 0);
        printf("rank = %ld\n", rank);
        mzd_free(A);
    }

    else if (!strcmp(argv[1], "buildPolynomialBasisMatrix")) {
        if (argc != 3) {
            printf("%s buildPolynomialBasisMatrix variant_dir\n", argv[0]);
            printf("    * variant_dir    a directory where to store the polynomial basis\n");
            return 2;
        }
        buildPolynomialBasisMatrix(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "buildBasisMatrices")) {
        if (argc != 3) {
            printf("%s buildBasisMatrices variant_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            return 2;
        }
        buildBasisMatrices(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "buildBasisHMatrix")) {
        buildBasisHMatrix(&Elisabeth4);
    }

    else if (!strcmp(argv[1], "testBasisMatrices")) {
        if (argc != 3) {
            printf("%s buildBasisMatrices variant_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            return 2;
        }
        testBasisMatricesElem(activeVariant, argv[2]);
        testBasisMatrices(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "reorderMonomials")) {
        monomial_order_init(12);
        mzd_t *A = mzd_from_png(argv[2], 0);
        A = reorderMonomials(A, 0, 0);
        printf("dim: %u %u\n", A->nrows, A->ncols);
        mzd_to_png(A, "Hreordered.png", 0, NULL, 0);
        mzd_free(A);
        monomial_order_free();
    }

    else if (!strcmp(argv[1], "inspectOrderedBasis")) {
        monomial_order_init(16);
        mzd_t *A = mzd_from_png(argv[2], 0);
        inspectOrderedBasis(A);
        mzd_free(A);
        monomial_order_free();
    }

    else if (!strcmp(argv[1], "testMonomialOrder")) {
        int i;
        morder *ord;
        int nvar = atoi(argv[2]);
        ord = morder_init(nvar, &drevlex);
        for (i = 0; i < ord->n; i++)
            printf("%d %d %04x\n", i, ord->perm[i], ord->perm[i]);
        morder_free(ord);
    }

    else if (!strcmp(argv[1], "testAltMonomialOrder")) {
        int i;
        morder *ord_sbl;
        int nvar = atoi(argv[2]);
        ord_sbl = morder_init(nvar, &sblex);
        for (i = 0; i < ord_sbl->n; i++)
            printf("%d %d\n", i, ord_sbl->perm[i]);
        morder_free(ord_sbl);
    }

    else if (!strcmp(argv[1], "testAltMonomialReorder")) {
        morder *ord_drl, *ord_sbl;
        int nvar = atoi(argv[2]);
        mzd_t *A, *B;
        ord_drl = morder_init(nvar, &drevlex);
        ord_sbl = morder_init(nvar, &sblex);

        A = mzd_from_png(argv[3], 0);
        B = mzd_copy(NULL, A);
        B = morder_reorder_columns(ord_drl->inv_P, B, 0);
        B = morder_reorder_columns(ord_drl->P, B, 0);
        if (mzd_equal(A, B)) printf("inv OK\n"); else printf("inv KO\n");
        A = morder_reorder_columns(ord_drl->inv_P, A, 0);
        mzd_to_png(A, "/tmp/debug.png", 0, NULL, 0);
        A = morder_reorder_columns(ord_sbl->P, A, 0);
        mzd_to_png(A, argv[4], 0, NULL, 0);
        mzd_free(A);
        morder_free(ord_drl);
        morder_free(ord_sbl);
    }

    else if (!strcmp(argv[1], "testImplem")) {
        nibble_t perm = {0, 3, 1, 2};
        mzd_t *A = constructMatrix(&Elisabeth4, perm);
        size_t rank = (size_t)mzd_echelonize(A, 0);
        printf("%lu\n", rank);
        mzd_to_png(A, "A_test.png", 0, NULL, 0);
        mzd_free(A);
    }

    // Generate keystream for test key
    else if (!strcmp(argv[1], "keystream")) {
        int i, n = atoi(argv[2]);
        ELI_state es;
        ELISABETH_init(&es, activeVariant, KEY, IV);
        for (i = 0; i < n; i++) {
            printf("%x", ELISABETH_next(&es));
        }
        printf("\n");
    }

    else if (!strcmp(argv[1], "testNibbleOrder")) {
        int i, j, jp;
        srandom(time(NULL));
        nibble_order_init(32);
        for (i = 0; i < 100; i++) {
            j = random();
            j = j % nibbles_len;
            printf("search %d ", j);
            print_nibble(nibbles + j);
            jp = binary_search(nibbles + j, nibbles, nibbles_len, sizeof(nibble_t), &cmp_nibble);
            printf(" %d done\n", jp);
        }
        nibble_order_free();
    }

    else if (!strcmp(argv[1], "buildInstance")) {
        if (argc != 4) {
            printf("%s buildInstance variant_dir instance_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            printf("    * instance_dir   a directory where the built instance will be stored\n");
            return 2;
        }
        buildInstance(activeVariant, argv[2], argv[3]);
    }
    else if (!strcmp(argv[1], "buildInstanceWithFiltering")) {
        if (argc != 5) {
            printf("%s buildInstance variant_dir instance_dir N'\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis and the precomputed ANF\n");
            printf("                     for all permutations\n");
            printf("    * instance_dir   a directory where the built instance will be stored\n");
            printf("    * N'             the number of key nibbles to consider in the attack\n");
            return 2;
        }
        buildInstanceWithFiltering(activeVariant, argv[2], argv[3], atoi(argv[4]));
    }
    else if (!strcmp(argv[1], "checkInstance")) {
        if (argc != 4) {
            printf("%s checkInstance variant_dir instance_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            printf("    * instance_dir   a directory where the instance to test can be found\n");
            return 2;
        }
        checkInstance(activeVariant, argv[2], argv[3]);
    }
    else if (!strcmp(argv[1], "checkInstanceWithFiltering")) {
        if (argc != 5) {
            printf("%s checkInstanceWithFiltering variant_dir instance_dir N'\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            printf("    * instance_dir   a directory where the instance to test can be found\n");
            printf("    * N'             the number of key nibbles considered in the attack\n");
            return 2;
        }
        checkInstanceWithFiltering(activeVariant, argv[2], argv[3], atoi(argv[4]));
    }


    else if (!strcmp(argv[1], "readInstance")) {
        if (argc != 4) {
            printf("%s readInstance variant_dir instance_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed anf for all permutations\n");
            printf("    * instance_dir   a directory where the instance to test can be found\n");
            return 2;
        }
        readInstance(activeVariant, argv[2], argv[3]);
    }

    else if (!strcmp(argv[1], "readPolynomialBasisMatrix")) {
        if (argc != 3) {
            printf("%s readPolynomialBasisMatrix variant_dir\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed ANF for all permutations\n");
            return 2;
        }
        readPolynomialBasisMatrix(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "printSolution")) {
        // usage ./main instance_dir
        if (argc != 3) {
            printf("%s readPolynomialBasisMatrix instance_dir\n", argv[0]);
            printf("    * instance_dir: a directory containing the solution file W\n");
            return 2;
        }
        printSolution(argv[2]);
    }
    else if (!strcmp(argv[1], "extractKey")) {
        char *job_name = NULL;
        if (argc != 4 && argc != 5) {
            printf("%s extractKey variant_dir instance_dir\n", argv[0]);
            printf("    * variant_dir          a directory containing the polynomial basis\n");
            printf("                           and the precomputed anf for all permutations\n");
            printf("    * instance_dir:        a directory containing the solution file [<job_name>-]W\n");
            printf("    * [optional] job_name: in case of a system build with filtering, the job_name\n");
            return 2;
        }
        if (argc == 5)
            job_name = argv[4];
        extractKey(activeVariant, argv[2], argv[3], job_name);
    }

    else if (!strcmp(argv[1], "checkSolutionInstanceWithFiltering")) {
        if (argc != 3) {
            printf("%s checkSolutionInstanceWithFiltering instance_dir\n", argv[0]);
            printf("    * instance_dir   a directory where the instance to test can be found\n");
            return 2;
        }
        checkSolutionInstanceWithFiltering(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "buildInstanceInit")) {
        if (argc != 3) {
            printf("%s buildInstanceInit instance_dir\n", argv[0]);
            printf("    * instance_dir   a directory where to create the instance \n");
            return 2;
        }
        buildInstanceInit(activeVariant, argv[2]);
    }

    else if (!strcmp(argv[1], "buildInstanceNext")) {
        if (argc != 6) {
            printf("%s buildInstanceNext variant_dir instance_dir Na Nb\n", argv[0]);
            printf("    * variant_dir    a directory containing the polynomial basis\n");
            printf("                     and the precomputed anf for all permutations\n");
            printf("    * instance_dir   the directory containing the instance \n");
            printf("    * Na, Nb         the key nibbles retained for the filtering are in\n");
            printf("                     subset {Na, ..., Nb-1}\n");
            return 2;
        }
        buildInstanceNext(activeVariant, argv[2], argv[3], atoi(argv[4]), atoi(argv[5]));
    }

    else if (!strcmp(argv[1], "buildInstanceFinalize")) {
        if (argc != 5) {
            printf("%s buildInstanceFinalize variant_dir instance_dir Na Nb\n", argv[0]);
            printf("    * variant_dir        a directory containing the polynomial basis\n");
            printf("                         and the precomputed anf for all permutations\n");
            printf("    * instance_dir       the directory containing the instance \n");
            printf("    * job_name           the job name generated by the call to buildInstanceNext\n");
            return 2;
        }
        buildInstanceFinalize(activeVariant, argv[2], argv[3], argv[4]);
    }
    return EXIT_SUCCESS;
}

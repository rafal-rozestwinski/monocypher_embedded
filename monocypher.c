// Monocypher version 3.1.1
//
// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2017-2020, Loup Vaillant
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2017-2020 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "monocypher.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(i, 0, size) (dst)[i] = (src)[i]
#define ZERO(buf, size)            FOR(i, 0, size) (buf)[i] = 0
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))

typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static const u8 zero[128] = {0};

// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, it's how many bytes we need to add to "align" x.
// Only works when pow_2 is a power of 2.
// Note: we use ~x+1 instead of -x to avoid compiler warnings
static size_t align(size_t x, size_t pow_2)
{
    return (~x + 1) & (pow_2 - 1);
}

static u32 load24_le(const u8 s[3])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
    return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

static void store64_le(u8 out[8], u64 in)
{
    store32_le(out    , (u32)in );
    store32_le(out + 4, in >> 32);
}

static void load32_le_buf (u32 *dst, const u8 *src, size_t size) {
    FOR(i, 0, size) { dst[i] = load32_le(src + i*4); }
}
static void load64_le_buf (u64 *dst, const u8 *src, size_t size) {
    FOR(i, 0, size) { dst[i] = load64_le(src + i*8); }
}
static void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
    FOR(i, 0, size) { store32_le(dst + i*4, src[i]); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
    FOR(i, 0, size) { store64_le(dst + i*8, src[i]); }
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int neq0(u64 diff)
{   // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    u64 half = (diff >> 32) | ((u32)diff);
    return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16])
{
    return (load64_le(a + 0) ^ load64_le(b + 0))
        |  (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[32],const u8 b[32]){return x16(a,b)| x16(a+16, b+16);}
static u64 x64(const u8 a[64],const u8 b[64]){return x32(a,b)| x32(a+32, b+32);}
int crypto_verify16(const u8 a[16], const u8 b[16]){ return neq0(x16(a, b)); }
int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }
int crypto_verify64(const u8 a[64], const u8 b[64]){ return neq0(x64(a, b)); }

static int zerocmp32(const u8 p[32])
{
    return crypto_verify32(p, zero);
}

void crypto_wipe(void *secret, size_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    ZERO(v_secret, size);
}

/////////////////
/// Chacha 20 ///
/////////////////
#define QUARTERROUND(a, b, c, d)     \
    a += b;  d = rotl32(d ^ a, 16);  \
    c += d;  b = rotl32(b ^ c, 12);  \
    a += b;  d = rotl32(d ^ a,  8);  \
    c += d;  b = rotl32(b ^ c,  7)

static void chacha20_rounds(u32 out[16], const u32 in[16])
{
    // The temporary variables make Chacha20 10% faster.
    u32 t0  = in[ 0];  u32 t1  = in[ 1];  u32 t2  = in[ 2];  u32 t3  = in[ 3];
    u32 t4  = in[ 4];  u32 t5  = in[ 5];  u32 t6  = in[ 6];  u32 t7  = in[ 7];
    u32 t8  = in[ 8];  u32 t9  = in[ 9];  u32 t10 = in[10];  u32 t11 = in[11];
    u32 t12 = in[12];  u32 t13 = in[13];  u32 t14 = in[14];  u32 t15 = in[15];

    FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
        QUARTERROUND(t0, t4, t8 , t12); // column 0
        QUARTERROUND(t1, t5, t9 , t13); // column 1
        QUARTERROUND(t2, t6, t10, t14); // column 2
        QUARTERROUND(t3, t7, t11, t15); // column 3
        QUARTERROUND(t0, t5, t10, t15); // diagonal 0
        QUARTERROUND(t1, t6, t11, t12); // diagonal 1
        QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
        QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
    }
    out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
    out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
    out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
    out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

static void chacha20_init_key(u32 block[16], const u8 key[32])
{
    load32_le_buf(block  , (const u8*)"expand 32-byte k", 4); // constant
    load32_le_buf(block+4, key                          , 8); // key
}

static u64 chacha20_core(u32 input[16], u8 *cipher_text, const u8 *plain_text,
                         size_t text_size)
{
    // Whole blocks
    u32    pool[16];
    size_t nb_blocks = text_size >> 6;
    FOR (i, 0, nb_blocks) {
        chacha20_rounds(pool, input);
        if (plain_text != 0) {
            FOR (j, 0, 16) {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p ^ load32_le(plain_text));
                cipher_text += 4;
                plain_text  += 4;
            }
        } else {
            FOR (j, 0, 16) {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p);
                cipher_text += 4;
            }
        }
        input[12]++;
        if (input[12] == 0) {
            input[13]++;
        }
    }
    text_size &= 63;

    // Last (incomplete) block
    if (text_size > 0) {
        if (plain_text == 0) {
            plain_text = zero;
        }
        chacha20_rounds(pool, input);
        u8 tmp[64];
        FOR (i, 0, 16) {
            store32_le(tmp + i*4, pool[i] + input[i]);
        }
        FOR (i, 0, text_size) {
            cipher_text[i] = tmp[i] ^ plain_text[i];
        }
        WIPE_BUFFER(tmp);
    }
    WIPE_BUFFER(pool);
    return input[12] + ((u64)input[13] << 32) + (text_size > 0);
}

void crypto_hchacha20(u8 out[32], const u8 key[32], const u8 in [16])
{
    u32 block[16];
    chacha20_init_key(block, key);
    // input
    load32_le_buf(block + 12, in, 4);
    chacha20_rounds(block, block);
    // prevent reversal of the rounds by revealing only half of the buffer.
    store32_le_buf(out   , block   , 4); // constant
    store32_le_buf(out+16, block+12, 4); // counter and nonce
    WIPE_BUFFER(block);
}

u64 crypto_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                        size_t text_size, const u8 key[32], const u8 nonce[8],
                        u64 ctr)
{
    u32 input[16];
    chacha20_init_key(input, key);
    input[12] = (u32) ctr;
    input[13] = (u32)(ctr >> 32);
    load32_le_buf(input+14, nonce, 2);
    ctr = chacha20_core(input, cipher_text, plain_text, text_size);
    WIPE_BUFFER(input);
    return ctr;
}

u32 crypto_ietf_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                             size_t text_size,
                             const u8 key[32], const u8 nonce[12], u32 ctr)
{
    u32 input[16];
    chacha20_init_key(input, key);
    input[12] = (u32) ctr;
    load32_le_buf(input+13, nonce, 3);
    ctr = (u32)chacha20_core(input, cipher_text, plain_text, text_size);
    WIPE_BUFFER(input);
    return ctr;
}

u64 crypto_xchacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                         size_t text_size,
                         const u8 key[32], const u8 nonce[24], u64 ctr)
{
    u8 sub_key[32];
    crypto_hchacha20(sub_key, key, nonce);
    ctr = crypto_chacha20_ctr(cipher_text, plain_text, text_size,
                              sub_key, nonce+16, ctr);
    WIPE_BUFFER(sub_key);
    return ctr;
}

void crypto_chacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
                     const u8 key[32], const u8 nonce[8])
{
    crypto_chacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);

}
void crypto_ietf_chacha20(u8 *cipher_text, const u8 *plain_text,
                          size_t text_size,
                          const u8 key[32], const u8 nonce[12])
{
    crypto_ietf_chacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);
}

void crypto_xchacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
                      const u8 key[32], const u8 nonce[24])
{
    crypto_xchacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);
}

/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->c <= 1_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
static void poly_block(crypto_poly1305_ctx *ctx)
{
    // s = h + c, without carry propagation
    const u64 s0 = ctx->h[0] + (u64)ctx->c[0]; // s0 <= 1_fffffffe
    const u64 s1 = ctx->h[1] + (u64)ctx->c[1]; // s1 <= 1_fffffffe
    const u64 s2 = ctx->h[2] + (u64)ctx->c[2]; // s2 <= 1_fffffffe
    const u64 s3 = ctx->h[3] + (u64)ctx->c[3]; // s3 <= 1_fffffffe
    const u32 s4 = ctx->h[4] +      ctx->c[4]; // s4 <=          5

    // Local all the things!
    const u32 r0 = ctx->r[0];       // r0  <= 0fffffff
    const u32 r1 = ctx->r[1];       // r1  <= 0ffffffc
    const u32 r2 = ctx->r[2];       // r2  <= 0ffffffc
    const u32 r3 = ctx->r[3];       // r3  <= 0ffffffc
    const u32 rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
    const u32 rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
    const u32 rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
    const u32 rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

    // (h + c) * r, without carry propagation
    const u64 x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0; // <= 97ffffe007fffff8
    const u64 x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1; // <= 8fffffe20ffffff6
    const u64 x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2; // <= 87ffffe417fffff4
    const u64 x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3; // <= 7fffffe61ffffff2
    const u32 x4 = s4 * (r0 & 3); // ...recover 2 bits    // <=                f

    // partial reduction modulo 2^130 - 5
    const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
    const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
    const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
    const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
    const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
    const u64 u4 = (u3 >> 32)     + (u5 & 3);

    // Update the hash
    ctx->h[0] = (u32)u0; // u0 <= 1_9ffffff0
    ctx->h[1] = (u32)u1; // u1 <= 1_97ffffe0
    ctx->h[2] = (u32)u2; // u2 <= 1_8fffffe2
    ctx->h[3] = (u32)u3; // u3 <= 1_87ffffe4
    ctx->h[4] = (u32)u4; // u4 <=          4
}

// (re-)initialises the input counter and input buffer
static void poly_clear_c(crypto_poly1305_ctx *ctx)
{
    ZERO(ctx->c, 4);
    ctx->c_idx = 0;
}

static void poly_take_input(crypto_poly1305_ctx *ctx, u8 input)
{
    size_t word = ctx->c_idx >> 2;
    size_t byte = ctx->c_idx & 3;
    ctx->c[word] |= (u32)input << (byte * 8);
    ctx->c_idx++;
}

static void poly_update(crypto_poly1305_ctx *ctx,
                        const u8 *message, size_t message_size)
{
    FOR (i, 0, message_size) {
        poly_take_input(ctx, message[i]);
        if (ctx->c_idx == 16) {
            poly_block(ctx);
            poly_clear_c(ctx);
        }
    }
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
    // Initial hash is zero
    ZERO(ctx->h, 5);
    // add 2^130 to every input block
    ctx->c[4] = 1;
    poly_clear_c(ctx);
    // load r and pad (r has some of its bits cleared)
    load32_le_buf(ctx->r  , key   , 4);
    load32_le_buf(ctx->pad, key+16, 4);
    FOR (i, 0, 1) { ctx->r[i] &= 0x0fffffff; }
    FOR (i, 1, 4) { ctx->r[i] &= 0x0ffffffc; }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
    if (message_size == 0) {
        return;
    }
    // Align ourselves with block boundaries
    size_t aligned = MIN(align(ctx->c_idx, 16), message_size);
    poly_update(ctx, message, aligned);
    message      += aligned;
    message_size -= aligned;

    // Process the message block by block
    size_t nb_blocks = message_size >> 4;
    FOR (i, 0, nb_blocks) {
        load32_le_buf(ctx->c, message, 4);
        poly_block(ctx);
        message += 16;
    }
    if (nb_blocks > 0) {
        poly_clear_c(ctx);
    }
    message_size &= 15;

    // remaining bytes
    poly_update(ctx, message, message_size);
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16])
{
    // Process the last block (if any)
    if (ctx->c_idx != 0) {
        // move the final 1 according to remaining input length
        // (We may add less than 2^130 to the last input block)
        ctx->c[4] = 0;
        poly_take_input(ctx, 1);
        // one last hash update
        poly_block(ctx);
    }

    // check if we should subtract 2^130-5 by performing the
    // corresponding carry propagation.
    const u64 u0 = (u64)5     + ctx->h[0]; // <= 1_00000004
    const u64 u1 = (u0 >> 32) + ctx->h[1]; // <= 1_00000000
    const u64 u2 = (u1 >> 32) + ctx->h[2]; // <= 1_00000000
    const u64 u3 = (u2 >> 32) + ctx->h[3]; // <= 1_00000000
    const u64 u4 = (u3 >> 32) + ctx->h[4]; // <=          5
    // u4 indicates how many times we should subtract 2^130-5 (0 or 1)

    // h + pad, minus 2^130-5 if u4 exceeds 3
    const u64 uu0 = (u4 >> 2) * 5 + ctx->h[0] + ctx->pad[0]; // <= 2_00000003
    const u64 uu1 = (uu0 >> 32)   + ctx->h[1] + ctx->pad[1]; // <= 2_00000000
    const u64 uu2 = (uu1 >> 32)   + ctx->h[2] + ctx->pad[2]; // <= 2_00000000
    const u64 uu3 = (uu2 >> 32)   + ctx->h[3] + ctx->pad[3]; // <= 2_00000000

    store32_le(mac     , (u32)uu0);
    store32_le(mac +  4, (u32)uu1);
    store32_le(mac +  8, (u32)uu2);
    store32_le(mac + 12, (u32)uu3);

    WIPE_CTX(ctx);
}

void crypto_poly1305(u8     mac[16],  const u8 *message,
                     size_t message_size, const u8  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, message, message_size);
    crypto_poly1305_final (&ctx, mac);
}

////////////////
/// Blake2 b ///
////////////////
static const u64 iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// increment the input offset
static void blake2b_incr(crypto_blake2b_ctx *ctx)
{
    u64   *x = ctx->input_offset;
    size_t y = ctx->input_idx;
    x[0] += y;
    if (x[0] < y) {
        x[1]++;
    }
}

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block)
{
    static const u8 sigma[12][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    };

    // init work vector
    u64 v0 = ctx->hash[0];  u64 v8  = iv[0];
    u64 v1 = ctx->hash[1];  u64 v9  = iv[1];
    u64 v2 = ctx->hash[2];  u64 v10 = iv[2];
    u64 v3 = ctx->hash[3];  u64 v11 = iv[3];
    u64 v4 = ctx->hash[4];  u64 v12 = iv[4] ^ ctx->input_offset[0];
    u64 v5 = ctx->hash[5];  u64 v13 = iv[5] ^ ctx->input_offset[1];
    u64 v6 = ctx->hash[6];  u64 v14 = iv[6] ^ (u64)~(is_last_block - 1);
    u64 v7 = ctx->hash[7];  u64 v15 = iv[7];

    // mangle work vector
    u64 *input = ctx->input;
#define BLAKE2_G(a, b, c, d, x, y)      \
    a += b + x;  d = rotr64(d ^ a, 32); \
    c += d;      b = rotr64(b ^ c, 24); \
    a += b + y;  d = rotr64(d ^ a, 16); \
    c += d;      b = rotr64(b ^ c, 63)
#define BLAKE2_ROUND(i)                                                 \
    BLAKE2_G(v0, v4, v8 , v12, input[sigma[i][ 0]], input[sigma[i][ 1]]); \
    BLAKE2_G(v1, v5, v9 , v13, input[sigma[i][ 2]], input[sigma[i][ 3]]); \
    BLAKE2_G(v2, v6, v10, v14, input[sigma[i][ 4]], input[sigma[i][ 5]]); \
    BLAKE2_G(v3, v7, v11, v15, input[sigma[i][ 6]], input[sigma[i][ 7]]); \
    BLAKE2_G(v0, v5, v10, v15, input[sigma[i][ 8]], input[sigma[i][ 9]]); \
    BLAKE2_G(v1, v6, v11, v12, input[sigma[i][10]], input[sigma[i][11]]); \
    BLAKE2_G(v2, v7, v8 , v13, input[sigma[i][12]], input[sigma[i][13]]); \
    BLAKE2_G(v3, v4, v9 , v14, input[sigma[i][14]], input[sigma[i][15]])

#ifdef BLAKE2_NO_UNROLLING
    FOR (i, 0, 12) {
        BLAKE2_ROUND(i);
    }
#else
    BLAKE2_ROUND(0);  BLAKE2_ROUND(1);  BLAKE2_ROUND(2);  BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);  BLAKE2_ROUND(5);  BLAKE2_ROUND(6);  BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);  BLAKE2_ROUND(9);  BLAKE2_ROUND(0);  BLAKE2_ROUND(1);
#endif

    // update hash
    ctx->hash[0] ^= v0 ^ v8;   ctx->hash[1] ^= v1 ^ v9;
    ctx->hash[2] ^= v2 ^ v10;  ctx->hash[3] ^= v3 ^ v11;
    ctx->hash[4] ^= v4 ^ v12;  ctx->hash[5] ^= v5 ^ v13;
    ctx->hash[6] ^= v6 ^ v14;  ctx->hash[7] ^= v7 ^ v15;
}

static void blake2b_set_input(crypto_blake2b_ctx *ctx, u8 input, size_t index)
{
    if (index == 0) {
        ZERO(ctx->input, 16);
    }
    size_t word = index >> 3;
    size_t byte = index & 7;
    ctx->input[word] |= (u64)input << (byte << 3);

}

static void blake2b_end_block(crypto_blake2b_ctx *ctx)
{
    if (ctx->input_idx == 128) {  // If buffer is full,
        blake2b_incr(ctx);        // update the input offset
        blake2b_compress(ctx, 0); // and compress the (not last) block
        ctx->input_idx = 0;
    }
}

static void blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    FOR (i, 0, message_size) {
        blake2b_end_block(ctx);
        blake2b_set_input(ctx, message[i], ctx->input_idx);
        ctx->input_idx++;
    }
}

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const u8           *key, size_t key_size)
{
    // initial hash
    COPY(ctx->hash, iv, 8);
    ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

    ctx->input_offset[0] = 0;         // beginning of the input, no offset
    ctx->input_offset[1] = 0;         // beginning of the input, no offset
    ctx->hash_size       = hash_size; // remember the hash size we want
    ctx->input_idx       = 0;

    // if there is a key, the first block is that key (padded with zeroes)
    if (key_size > 0) {
        u8 key_block[128] = {0};
        COPY(key_block, key, key_size);
        // same as calling crypto_blake2b_update(ctx, key_block , 128)
        load64_le_buf(ctx->input, key_block, 16);
        ctx->input_idx = 128;
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    if (message_size == 0) {
        return;
    }
    // Align ourselves with block boundaries
    size_t aligned = MIN(align(ctx->input_idx, 128), message_size);
    blake2b_update(ctx, message, aligned);
    message      += aligned;
    message_size -= aligned;

    // Process the message block by block
    FOR (i, 0, message_size >> 7) { // number of blocks
        blake2b_end_block(ctx);
        load64_le_buf(ctx->input, message, 16);
        message += 128;
        ctx->input_idx = 128;
    }
    message_size &= 127;

    // remaining bytes
    blake2b_update(ctx, message, message_size);
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash)
{
    // Pad the end of the block with zeroes
    FOR (i, ctx->input_idx, 128) {
        blake2b_set_input(ctx, 0, i);
    }
    blake2b_incr(ctx);        // update the input offset
    blake2b_compress(ctx, 1); // compress the last block
    size_t nb_words = ctx->hash_size >> 3;
    store64_le_buf(hash, ctx->hash, nb_words);
    FOR (i, nb_words << 3, ctx->hash_size) {
        hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
    }
    WIPE_CTX(ctx);
}

void crypto_blake2b_general(u8       *hash   , size_t hash_size,
                            const u8 *key    , size_t key_size,
                            const u8 *message, size_t message_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, hash_size, key, key_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(u8 hash[64], const u8 *message, size_t message_size)
{
    crypto_blake2b_general(hash, 64, 0, 0, message, message_size);
}


/// !!!!!!!!!!!!!! CUT A LOT !!!!!!!!!!!!!!!!!!!!!!!!!!!

////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////
static void lock_auth(u8 mac[16], const u8  auth_key[32],
                      const u8 *ad         , size_t ad_size,
                      const u8 *cipher_text, size_t text_size)
{
    u8 sizes[16]; // Not secret, not wiped
    store64_le(sizes + 0, ad_size);
    store64_le(sizes + 8, text_size);
    crypto_poly1305_ctx poly_ctx;           // auto wiped...
    crypto_poly1305_init  (&poly_ctx, auth_key);
    crypto_poly1305_update(&poly_ctx, ad         , ad_size);
    crypto_poly1305_update(&poly_ctx, zero       , align(ad_size, 16));
    crypto_poly1305_update(&poly_ctx, cipher_text, text_size);
    crypto_poly1305_update(&poly_ctx, zero       , align(text_size, 16));
    crypto_poly1305_update(&poly_ctx, sizes      , 16);
    crypto_poly1305_final (&poly_ctx, mac); // ...here
}

void crypto_lock_aead(u8 mac[16], u8 *cipher_text,
                      const u8  key[32], const u8  nonce[24],
                      const u8 *ad        , size_t ad_size,
                      const u8 *plain_text, size_t text_size)
{
    u8 sub_key[32];
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    crypto_hchacha20(sub_key, key, nonce);
    crypto_chacha20(auth_key, 0, 64, sub_key, nonce + 16);
    crypto_chacha20_ctr(cipher_text, plain_text, text_size,
                        sub_key, nonce + 16, 1);
    lock_auth(mac, auth_key, ad, ad_size, cipher_text, text_size);
    WIPE_BUFFER(sub_key);
    WIPE_BUFFER(auth_key);
}

int crypto_unlock_aead(u8 *plain_text, const u8 key[32], const u8 nonce[24],
                       const u8  mac[16],
                       const u8 *ad         , size_t ad_size,
                       const u8 *cipher_text, size_t text_size)
{
    u8 sub_key[32];
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    crypto_hchacha20(sub_key, key, nonce);
    crypto_chacha20(auth_key, 0, 64, sub_key, nonce + 16);
    u8 real_mac[16];
    lock_auth(real_mac, auth_key, ad, ad_size, cipher_text, text_size);
    WIPE_BUFFER(auth_key);
    if (crypto_verify16(mac, real_mac)) {
        WIPE_BUFFER(sub_key);
        WIPE_BUFFER(real_mac);
        return -1;
    }
    crypto_chacha20_ctr(plain_text, cipher_text, text_size,
                        sub_key, nonce + 16, 1);
    WIPE_BUFFER(sub_key);
    WIPE_BUFFER(real_mac);
    return 0;
}

void crypto_lock(u8 mac[16], u8 *cipher_text,
                 const u8 key[32], const u8 nonce[24],
                 const u8 *plain_text, size_t text_size)
{
    crypto_lock_aead(mac, cipher_text, key, nonce, 0, 0, plain_text, text_size);
}

int crypto_unlock(u8 *plain_text,
                  const u8 key[32], const u8 nonce[24], const u8 mac[16],
                  const u8 *cipher_text, size_t text_size)
{
    return crypto_unlock_aead(plain_text, key, nonce, mac, 0, 0,
                              cipher_text, text_size);
}

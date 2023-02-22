/*
 * Implementing extraction of Falcon values.
 */

#include <stdio.h>

#include "extract.h"
#include "inner.h"
#include "utils.h"

static int
get_ct(const void *sig, size_t sig_len, int sig_type)
{
    const uint8_t *es = (uint8_t *) sig;
    unsigned logn = es[0] & 0x0F;

    int ct = 0;
    switch (sig_type) {
    case 0:
        switch (es[0] & 0xF0) {
        case 0x30:
            break;
        case 0x50:
            if (sig_len != FALCON_SIG_CT_SIZE(logn)) {
                return FALCON_ERR_FORMAT;
            }
            ct = 1;
            break;
        default:
            return FALCON_ERR_BADSIG;
        }
        break;
    case FALCON_SIG_COMPRESSED:
    case FALCON_SIG_DETERMINISTIC:
        if ((es[0] & 0xF0) != 0x30) {
            return FALCON_ERR_FORMAT;
        }
        break;
    case FALCON_SIG_PADDED:
        if ((es[0] & 0xF0) != 0x30) {
            return FALCON_ERR_FORMAT;
        }
        if (sig_len != FALCON_SIG_PADDED_SIZE(logn)) {
            return FALCON_ERR_FORMAT;
        }
        break;
    case FALCON_SIG_CT:
        if ((es[0] & 0xF0) != 0x50) {
            return FALCON_ERR_FORMAT;
        }
        if (sig_len != FALCON_SIG_CT_SIZE(logn)) {
            return FALCON_ERR_FORMAT;
        }
        ct = 1;
        break;
    default:
        return FALCON_ERR_BADARG;
    }

    return ct;
}

int
extract_falcon_hash(
    unsigned logn,
    const void* nonce, size_t nonce_length,
    const void* data, size_t data_length,
    void* hm)
{
    /*
     * Compute hash used in falcon signature type FALCON_SIG_DETERMINISTIC
     * Given nonce and data
     */

    shake256_context hash_data;
    shake256_init(&hash_data);

    // inject nonce to hash
    shake256_inject(&hash_data, nonce, nonce_length);

    // inject data to hash
    // now hash input is nonce|data
    shake256_inject(&hash_data, data, data_length);

    // hash message to point
    // copied corresponding hash function from falcon_fun.cpp
    shake256_flip(&hash_data);
    Zf(hash_to_point_vartime)(
        (inner_shake256_context *)&hash_data, (uint16_t *)hm, logn);

    return 0;
}

int
extract_s1(
    const int16_t *s2, uint16_t *decoded_pk,
    unsigned logn, int ct,
    shake256_context *hash_data,
    void *tmp, size_t tmp_len,
    void *s1)
{

    size_t n = (size_t)1 << logn, u;
    uint16_t *hm = (uint16_t *)align_u16(tmp);
    uint8_t *atmp = (uint8_t *)(hm + n);
    int16_t *tmp_s1 = (int16_t *) s1;

    if (tmp_len < FALCON_TMPSIZE_VERIFY(logn)) {
        return FALCON_ERR_SIZE;
    }

    /*
     * Hash message to point.
     */
    shake256_flip(hash_data);
    if (ct) {
        Zf(hash_to_point_ct)(
            (inner_shake256_context *)hash_data, hm, logn, atmp);
    } else {
        Zf(hash_to_point_vartime)(
            (inner_shake256_context *)hash_data, hm, logn);
    }

    /*
     * obtain -s1
     */
    Zf(to_ntt_monty)(decoded_pk, logn);
    if (!Zf(verify_raw)(hm, s2, decoded_pk, logn, atmp)) {
        return FALCON_ERR_BADSIG;
    }

    // output s1

    int16_t *att = (int16_t *)atmp;

    for (int j = 0; j < n; j++){
        tmp_s1[j] = -att[j];
    }
    return 0;
}

int
extract_decoded_pk(
    const uint8_t *pubkey, size_t pubkey_len, void *decoded_pk)
{
    if (pubkey_len == 0) {
        return FALCON_ERR_FORMAT;
    }

    if ((pubkey[0] & 0xF0) != 0x00) {
        return FALCON_ERR_FORMAT;
    }

    unsigned logn = pubkey[0] & 0x0F;
    if (logn < 1 || logn > 10) {
        return FALCON_ERR_FORMAT;
    }

    if (pubkey_len != FALCON_PUBKEY_SIZE(logn)) {
        return FALCON_ERR_FORMAT;
    }

    uint16_t *tmp_decoded_pk = (uint16_t *) decoded_pk;
    if (Zf(modq_decode)(tmp_decoded_pk, logn,
                        pubkey + 1, pubkey_len - 1) != pubkey_len - 1) {
        return FALCON_ERR_FORMAT;
    }

    return 0;
}

int
extract_s2(const void *sig, size_t sig_len, int sig_type, int ct, void *s2)
{
    const uint8_t *es = (uint8_t *) sig;

    if (sig_len < 41) {
        return FALCON_ERR_FORMAT;
    }

    unsigned logn = es[0] & 0x0F;
    if (logn < 1 || logn > 10) {
        return FALCON_ERR_FORMAT;
    }

    if (ct != get_ct(sig, sig_len, sig_type)){
        return FALCON_ERR_BADARG;
    }

    if (ct < 0) {
        return ct;
    }

    /*
     * Decode signature value to extract s2.
     */
    int16_t *sv = (int16_t *) s2;
    size_t u = (sig_type == FALCON_SIG_DETERMINISTIC) ? 1 : 41, v;

    if (ct) {
        v = Zf(trim_i16_decode)(sv, logn,
            Zf(max_sig_bits)[logn], es + u, sig_len - u);
    } else {
        v = Zf(comp_decode)(sv, logn, es + u, sig_len - u);
    }

    /*
     * Final format check
     */
    if (v == 0) {
        return FALCON_ERR_FORMAT;
    }
    if ((u + v) != sig_len) {
        /*
         * Extra bytes of value 0 are tolerated only for the
         * "padded" format.
         */
        if ((sig_type == 0 && sig_len == FALCON_SIG_PADDED_SIZE(logn))
            || sig_type == FALCON_SIG_PADDED) {
            while (u + v < sig_len) {
                if (es[u + v] != 0) {
                    return FALCON_ERR_FORMAT;
                }
                v ++;
            }
        } else {
            return FALCON_ERR_FORMAT;
        }
    }

    return 0;
}

int
extract_falcon_values(const void *sig, size_t sig_len, int sig_type,
    const void *pubkey, size_t pubkey_len,
    const void *data, size_t data_len,
    void *tmp, size_t tmp_len,
    void *s1, void *s2, void *decoded_pk)
{
    // create hash context for generating HashToPoint(pubkey|m, q, n)
    shake256_context hd;
    int r;

    // init hashdata and inject the pubkey (first 40 bytes in sig)
    // now hash input is pubkey
    shake256_init(&hd);
    shake256_inject(&hd, pubkey, pubkey_len);

    // inject data to hash
    // now hash input is pubkey|data
    shake256_inject(&hd, data, data_len);

    // start to extract
    r = extract_decoded_pk(pubkey, pubkey_len, decoded_pk);
    if (r < 0) {
        return r;
    }

    int ct = get_ct(sig, sig_len, sig_type);
    if (ct < 0) {
        return ct;
    }

    r = extract_s2(sig, sig_len, sig_type, ct, s2);
    if (r < 0) {
        return r;
    }

    int logn = falcon_get_logn(pubkey, pubkey_len);
    if (logn < 0) {
        // return if falcon_get_logn failed, logn is actually error code
        return logn;
    }
    size_t n = (size_t)1 << (unsigned)logn;
    uint16_t *tmp_decoded_pk = (uint16_t *) xmalloc(n * sizeof(uint16_t));
    memcpy(tmp_decoded_pk, decoded_pk, n * sizeof(uint16_t));

    r = extract_s1(s2, tmp_decoded_pk, logn, ct, &hd, tmp, tmp_len, s1);

    xfree(tmp_decoded_pk);

    if (r < 0) {
        return r;
    }

    return 0;
}

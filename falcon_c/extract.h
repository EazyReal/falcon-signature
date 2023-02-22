/*
 * Extracting Falcon values.
 */

#ifndef EXTRACT_H__
#define EXTRACT_H__

#include <stdint.h>
#include <stddef.h>

#include "falcon.h"

#ifdef __cplusplus
extern "C" {
#endif

int extract_falcon_hash(unsigned logn,
    const void* nonce, size_t nonce_length,
    const void* data, size_t data_length,
    void* hm);

int extract_s1(const int16_t *s2, uint16_t *decoded_pk,
    unsigned logn, int ct,
    shake256_context *hash_data,
    void *tmp, size_t tmp_len,
    void *s1);

int extract_s2(const void *sig, size_t sig_len, int sig_type, int ct,
    void *s2);

int extract_decoded_pk(const uint8_t *pubkey, size_t pubkey_len,
    void *decoded_pk);

int extract_falcon_values(const void *sig, size_t sig_len, int sig_type,
    const void *pubkey, size_t pubkey_len,
    const void *data, size_t data_len,
    void *tmp, size_t tmp_len,
    void *s1, void *s2, void *decoded_pk);

#ifdef __cplusplus
}
#endif

#endif


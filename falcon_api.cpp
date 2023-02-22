#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>

#include "falcon_api.hpp"
// #include "parameters.hpp"

#define LOGN 9

// include falcon
extern "C"
{
#include "falcon_c/falcon.h"
#include "falcon_c/extract.h"
}

static size_t get_buf_size(unsigned logn)
{
    size_t len = std::max({FALCON_TMPSIZE_KEYGEN(logn),
                           FALCON_TMPSIZE_SIGNDYN(logn),
                           FALCON_TMPSIZE_SIGNTREE(logn),
                           FALCON_TMPSIZE_EXPANDPRIV(logn),
                           FALCON_TMPSIZE_VERIFY(logn)});
    return len;
}

KeyPair falcon_create_keyPair(unsigned logn)
{
    size_t publicKeyLength = FALCON_PUBKEY_SIZE(logn);
    size_t privateKeyLength = FALCON_PRIVKEY_SIZE(logn);
    std::unique_ptr<uint8_t[]> publicKeyData(new uint8_t[publicKeyLength]());
    std::unique_ptr<uint8_t[]> privateKeyData(new uint8_t[privateKeyLength]());

    size_t buffer_len = get_buf_size(logn);
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_len]);

    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0)
    {
        throw std::runtime_error("random seeding failed");
    }

    int r = falcon_keygen_make(&rng, logn,
                               privateKeyData.get(), privateKeyLength,
                               publicKeyData.get(), publicKeyLength,
                               buffer.get(), buffer_len);

    if (r != 0)
    {
        std::string err_msg = "key gen ERR: ";
        err_msg += std::to_string(r);
        throw std::runtime_error(err_msg);
    }

    std::vector<uint8_t> publicKey(publicKeyData.get(),
                                   publicKeyData.get() + publicKeyLength);
    std::vector<uint8_t> privateKey(privateKeyData.get(),
                                    privateKeyData.get() + privateKeyLength);

    KeyPair keyPair(publicKey, privateKey);
    return keyPair;
}

std::vector<uint8_t> falcon_sign(const std::vector<uint8_t> &content,
                                 const std::vector<uint8_t> &privateKey)
{
    shake256_context rng;
    if (shake256_init_prng_from_system(&rng) != 0)
    {
        throw std::logic_error("random seeding failed");
    }

    size_t sig_len = FALCON_SIG_DETERMINISTIC_MAXSIZE(LOGN);
    std::unique_ptr<uint8_t[]> sig(new uint8_t[sig_len]);

    size_t buffer_len = get_buf_size(LOGN);
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_len]);

    int r = falcon_sign_dyn(&rng,
                            sig.get(), &sig_len, FALCON_SIG_DETERMINISTIC,
                            privateKey.data(), privateKey.size(),
                            content.data(), content.size(),
                            buffer.get(), buffer_len);

    if (r != 0)
    {
        std::string err_msg = "sign ERR: ";
        err_msg += std::to_string(r);
        throw std::logic_error(err_msg);
    }

    std::vector<uint8_t> result(sig.get(), sig.get() + sig_len);

    return result;
}

bool falcon_verify(const std::vector<uint8_t> &content,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &publicKey)
{
    // init temp memory for computation in flacon
    size_t buffer_len = get_buf_size(LOGN);
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_len]);

    // do falcon verification
    // note we use our own signature type of falcon
    // "FALCON_SIG_DETERMINISTIC"
    int r = falcon_verify(
        signature.data(), signature.size(), FALCON_SIG_DETERMINISTIC,
        publicKey.data(), publicKey.size(),
        content.data(), content.size(),
        buffer.get(), buffer_len);

    return r == 0;
}

void decode_falcon_stuff(const std::vector<uint8_t> &sig,
                         const std::vector<uint8_t> &pubkey,
                         const std::vector<uint8_t> &data,
                         std::vector<int16_t> &s1, std::vector<int16_t> &s2,
                         std::vector<uint16_t> &decoded_pk)
{
    // Check for passed-in capacity for result values
    size_t expected_result_capacity = static_cast<size_t>(1ul << LOGN);
    if (s1.capacity() < expected_result_capacity)
        s1.reserve(expected_result_capacity);
    if (s2.capacity() < expected_result_capacity)
        s2.reserve(expected_result_capacity);
    if (decoded_pk.capacity() < expected_result_capacity)
        decoded_pk.reserve(expected_result_capacity);

    int sig_type = FALCON_SIG_DETERMINISTIC;

    // init temp memory for computation in flacon
    size_t buffer_len = get_buf_size(LOGN);
    std::unique_ptr<uint8_t[]> buffer(new uint8_t[buffer_len]);

    int r = extract_falcon_values(
        sig.data(), sig.size(), sig_type,
        pubkey.data(), pubkey.size(),
        data.data(), data.size(),
        buffer.get(), buffer_len,
        &s1[0], &s2[0], &decoded_pk[0]);

    if (r < 0)
        throw std::logic_error("Decoding Falcon Stuff Error");
}

std::vector<uint16_t> falcon_hash(const std::vector<uint8_t> &nonce,
                                  const std::vector<uint8_t> &data)
{
    size_t n = static_cast<size_t>(1ul << LOGN);
    std::vector<uint16_t> hm(n, 0);
    int r = extract_falcon_hash(LOGN,
                                nonce.data(), nonce.size(),
                                data.data(), data.size(), &hm[0]);
    if (r < 0)
        throw std::logic_error("Falcon hash error");

    return hm;
}

std::vector<std::vector<uint16_t>> get_decoded_pks(
    const std::vector<std::vector<uint8_t>> &publicKeys)
{
    std::vector<std::vector<uint16_t>> decoded_pk_array;
    size_t pk_len = FALCON_PUBKEY_SIZE(LOGN);
    for (size_t i = 0; i < publicKeys.size(); i++)
    {
        std::vector<uint16_t> decoded_pk(pk_len, 0);
        extract_decoded_pk(publicKeys[i].data(), pk_len, &decoded_pk[0]);
        decoded_pk_array.emplace_back(decoded_pk);
    }
    return decoded_pk_array;
}

std::vector<int16_t> get_decoded_s2(const std::vector<uint8_t> &signature)
{
    size_t n = static_cast<size_t>(1ul << LOGN);
    std::vector<int16_t> decoded_s2(n, 0);
    int ct = 0; // ct is 0 for sig_type FALCON_SIG_DETERMINISTIC we used
    extract_s2(signature.data(), signature.size(), FALCON_SIG_DETERMINISTIC, ct, &decoded_s2[0]);
    return decoded_s2;
}

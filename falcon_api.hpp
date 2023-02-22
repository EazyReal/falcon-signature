#ifndef FALCON_API_HPP
#define FALCON_API_HPP

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

struct KeyPair
{
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> privateKey;
    KeyPair(){};
    KeyPair(std::vector<uint8_t> pubKey, std::vector<uint8_t> priKey)
        : publicKey(std::move(pubKey)), privateKey(std::move(priKey)) {}
};

KeyPair falcon_create_keyPair(unsigned logn);

std::vector<uint8_t> falcon_sign(
    const std::vector<uint8_t> &content,
    const std::vector<uint8_t> &privateKey);

bool falcon_verify(const std::vector<uint8_t> &content,
                   const std::vector<uint8_t> &signature,
                   const std::vector<uint8_t> &publicKey);

void decode_falcon_stuff(const std::vector<uint8_t> &sig,
                         const std::vector<uint8_t> &pubkey,
                         const std::vector<uint8_t> &data,
                         std::vector<int16_t> &s1, std::vector<int16_t> &s2,
                         std::vector<uint16_t> &decoded_pk);

std::vector<uint16_t> falcon_hash(const std::vector<uint8_t> &nonce,
                                  const std::vector<uint8_t> &data);

std::vector<std::vector<uint16_t>> get_decoded_pks(
    const std::vector<std::vector<uint8_t>> &publicKeys);

std::vector<int16_t> get_decoded_s2(const std::vector<uint8_t> &signature);

#endif

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <boost/program_options.hpp>

#include "falcon_api.hpp"

using namespace std;

namespace po = boost::program_options;

#define LOGN 9

template <typename T>
std::ostream &operator<<(std::ostream &os, const std::vector<T> &v)
{
    // os << "[ ";
    for (const auto &elem : v)
    {
        os << elem << " ";
    }
    // os << "]";
    return os;
}

int main(int argc, const char *argv[])
{
    po::options_description desc("Test C++ Falcon API");
    desc.add_options()("help", "print help message")("n", po::value<size_t>(), "number of trials")("t", "test falcon correctness");

    po::positional_options_description pod;
    pod.add("n", -1);

    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).options(desc).positional(pod).run(), vm);
    po::notify(vm);

    if (vm.count("help") || vm.count("n") == 0)
    {
        cout << desc << "\n";
        return 1;
    }

    size_t testCount = vm["n"].as<size_t>();

    while (testCount > 0)
    {
        // Do falcon keygen
        KeyPair keypair = falcon_create_keyPair(LOGN);

        // Generate message
        size_t contentLength = static_cast<size_t>(rand() % 1009);
        vector<uint8_t> contentBytes(contentLength, 0);
        for (auto b : contentBytes)
            b = static_cast<uint8_t>(rand() % 256);

        // Do falcon signing
        vector<uint8_t> signature = falcon_sign(contentBytes,
                                                keypair.privateKey);

        // reserve the capicity for c...
        std::vector<int16_t> s1(512, 0);
        std::vector<int16_t> s2(512, 0);
        std::vector<uint16_t> dpk(512, 0);
        decode_falcon_stuff(signature, keypair.publicKey, contentBytes, s1, s2, dpk);
        // deterministic sign => nonce = 0 len?
        std::vector<uint8_t> empty_nonce = {};
        std::vector<uint16_t> hm = falcon_hash(empty_nonce, contentBytes);

        std::cout << s1 << std::endl
                  << s2 << std::endl
                  << dpk << std::endl
                  << hm << std::endl;

        if (vm.count("t"))
        {
            // Test Verifying
            if (!falcon_verify(contentBytes, signature, keypair.publicKey))
                throw std::logic_error("");

            // Make sure that slightly altered message cannot be verified
            size_t tempByteIndex = static_cast<size_t>(
                rand() % contentBytes.size());
            uint8_t tempContentByte = contentBytes[tempByteIndex];
            if (tempContentByte == 0)
                contentBytes[tempByteIndex] = 1;
            else
                contentBytes[tempByteIndex] = 0;

            if (falcon_verify(contentBytes, signature, keypair.publicKey))
                throw std::logic_error("");

            contentBytes[tempByteIndex] = tempContentByte;

            // Make sure that slightly altered signature cannot be verified
            tempByteIndex = static_cast<size_t>(rand() % signature.size());
            uint8_t tempSignatureByte = signature[tempByteIndex];
            if (tempContentByte == 0)
                signature[tempByteIndex] = 1;
            else
                signature[tempByteIndex] = 0;

            if (falcon_verify(contentBytes, signature, keypair.publicKey))
                throw std::logic_error("");

            signature[tempByteIndex] = tempSignatureByte;

            // Make sure that signature cannot be verified with incorrect publickey
            tempByteIndex = static_cast<size_t>(
                rand() % keypair.publicKey.size());
            uint8_t tempPKByte = keypair.publicKey[tempByteIndex];
            if (tempPKByte == 0)
                keypair.publicKey[tempByteIndex] = 1;
            else
                keypair.publicKey[tempByteIndex] = 0;

            if (falcon_verify(contentBytes, signature, keypair.publicKey))
                throw std::logic_error("");
            keypair.publicKey[tempByteIndex] = tempPKByte;
        }

        testCount--;
    }

    // print if success
    std::cout << "Success!" << std::endl;
    return 0;
}

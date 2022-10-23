#include <iostream>
#include <string>
#include <gtest/gtest.h>
#include "kuznechik.h"
#include <chrono>

using std::vector;
//
TEST(Correctness_generate_keys, wiki) {
    std::vector<std::string> correct{"8899aabbccddeeff0011223344556677",
                                     "fedcba98765432100123456789abcdef",
                                     "db31485315694343228d6aef8cc78c44",
                                     "3d4553d8e9cfec6815ebadc40a9ffd04",
                                     "57646468c44a5e28d3e59246f429f1ac",
                                     "bd079435165c6432b532e82834da581b",
                                     "51e640757e8745de705727265a0098b1",
                                     "5a7925017b9fdd3ed72a91a22286f984",
                                     "bb44e25378c73123a5f32f73cdb6e517",
                                     "72e9dd7416bcf45b755dbaa88e4a4043"};

    KuznechikCipher kuznechik("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    auto keys = kuznechik.get_keys();

    ASSERT_EQ(keys.size(), correct.size());

    for (size_t i = 0; i < keys.size(); ++i) {
        ASSERT_EQ(keys[i], correct[i]);
    }
}

TEST(Correctness_encoding, wiki) {
    std::string correct("7f679d90bebc24305a468d42b9d4edcd");

    KuznechikCipher kuznechik("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    auto blk = hex2bin("1122334455667700ffeeddccbbaa9988");
    auto [first, second] = kuznechik.encode_block(blk);
    blk[0] = uint8_t(first >> 56), blk[1] = uint8_t(first >> 48), blk[2] = uint8_t(first >> 40), blk[3] = uint8_t(
            first >> 32), blk[4] = uint8_t(first >> 24), blk[5] = uint8_t(first >> 16), blk[6] = uint8_t(
            first >> 8), blk[7] = uint8_t(first);
    blk[8] = uint8_t(second >> 56), blk[9] = uint8_t(second >> 48), blk[10] = uint8_t(second >> 40), blk[11] = uint8_t(
            second >> 32), blk[12] = uint8_t(second >> 24), blk[13] = uint8_t(second >> 16), blk[14] = uint8_t(
            second >> 8), blk[15] = uint8_t(second);
    auto res = convert_uint_arr_to_str(blk);
    ASSERT_EQ(res, correct);
}


TEST(Correctness_dencoding, wiki) {
    std::string correct("1122334455667700ffeeddccbbaa9988");

    KuznechikCipher kuznechik("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    uint64_t first = 9180479610418897968, second = 6505042029508357581;
    std::vector<uint8_t> blk(16);
    kuznechik.decode_block(first, second);
    blk[0] = uint8_t(first >> 56), blk[1] = uint8_t(first >> 48), blk[2] = uint8_t(first >> 40), blk[3] = uint8_t(
            first >> 32), blk[4] = uint8_t(first >> 24), blk[5] = uint8_t(first >> 16), blk[6] = uint8_t(
            first >> 8), blk[7] = uint8_t(first);
    blk[8] = uint8_t(second >> 56), blk[9] = uint8_t(second >> 48), blk[10] = uint8_t(second >> 40), blk[11] = uint8_t(
            second >> 32), blk[12] = uint8_t(second >> 24), blk[13] = uint8_t(second >> 16), blk[14] = uint8_t(
            second >> 8), blk[15] = uint8_t(second);
    auto str_res = convert_uint_arr_to_str(blk);
    ASSERT_EQ(str_res, correct);
}


TEST(Bench_encoding, wiki) {
    KuznechikCipher kuznechik("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    size_t num = 1024 * 1024 * 100 / 16;

    auto blk_1 = hex2bin("1122334455667700ffeeddccbbaa9988");

    vector<vector<uint8_t>> blocks;
    for (size_t i = 0; i < num; ++i) {
        blocks.push_back(hex2bin("1122334455667700ffeeddccbbaa9988"));
    }

    vector<std::pair<uint64_t, uint64_t>> res;
    res.reserve(1024 * 1024 * 100 / 16);

    auto start = std::chrono::high_resolution_clock::now();


    for (auto &blk: blocks) {
        res.push_back(kuznechik.encode_block(blk));
    }

    auto stop = std::chrono::high_resolution_clock::now();
    std::cout << "\n\nEncoding elapsed time for 100mb: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count()
              << "\n\n";;
}

TEST(Bench_dencoding, wiki) {
    KuznechikCipher kuznechik("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");

    size_t num = 1024 * 1024 * 100 / 16;

    uint64_t first = 9180479610418897968, second = 6505042029508357581;
    vector<uint8_t> blk(16);

    std::vector<std::pair<uint64_t, uint64_t>> res(1024 * 1024 * 100 / 16, {9180479610418897968, 6505042029508357581});


    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < num; ++i) {
        kuznechik.decode_block(res[i].first, res[i].second);
    }

    auto stop = std::chrono::high_resolution_clock::now();

    std::cout << "\n\nDecoding elapsed time for 100mb: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count()
              << "\n\n";


}


int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}

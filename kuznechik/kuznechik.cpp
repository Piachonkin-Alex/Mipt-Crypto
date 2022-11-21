#include "kuznechik.hpp"

KuznechikCipher::KuznechikCipher(const std::string &key) {
    if (key.size() != 64) {
        throw std::runtime_error("bad key length!");
    }

    vector<uint8_t> vec = utils::hex2bin(key);

    vector<vector<uint8_t>> multiplications(256, vector<uint8_t>(256));

    for (size_t i = 1; i < 256; ++i) { // calc multiplications using indices modulo 2^a
        for (size_t j = 1; j < 256; ++j) {
            auto ind_i = index_galua_pows[i - 1], ind_j = index_galua_pows[j - 1];
            multiplications[i][j] = galua_pows[(ind_i + ind_j) % 255];
        }
    }

    for (size_t ind = 0; ind < 16; ++ind) {
        for (size_t byte = 0; byte < 256; ++byte) {
            vector<uint8_t> blk(16);
            blk[ind] = static_cast<uint8_t>(byte);
            for (size_t it = 0; it < 16; ++it) {
                uint8_t score = 0;
                for (size_t l_ind = 0; l_ind < 16; ++l_ind) {
                    score ^= multiplications[linear_arr_[15 - l_ind]][blk[(l_ind + 16 - it) % 16]];
                }
                blk[15 - it] = score;
            }
            linear_table_[ind][byte] = blk;
            linear_table_64_[ind][byte][0] = utils::convert8uint8t(blk[0], blk[1], blk[2], blk[3], blk[4], blk[5],
                                                                   blk[6],
                                                                   blk[7]);
            linear_table_64_[ind][byte][1] = utils::convert8uint8t(blk[8], blk[9], blk[10], blk[11], blk[12],
                                                                   blk[13],
                                                                   blk[14], blk[15]);

        }
    }

    for (size_t ind = 0; ind < 16; ++ind) {
        for (size_t byte = 0; byte < 256; ++byte) {
            vector<uint8_t> blk(16);
            blk[ind] = static_cast<uint8_t>(byte);

            for (size_t it = 0; it < 16; ++it) {
                uint8_t score = 0;
                for (size_t l_ind = 0; l_ind < 16; ++l_ind) {
                    score ^= multiplications[linear_arr_[l_ind]][blk[(l_ind + it) % 16]];
                }
                blk[it] = score;
            }

            inv_linear_table_[ind][byte] = blk;
            inv_linear_table_64_[ind][byte][0] = utils::convert8uint8t(blk[0], blk[1], blk[2], blk[3], blk[4],
                                                                       blk[5],
                                                                       blk[6], blk[7]);
            inv_linear_table_64_[ind][byte][1] = utils::convert8uint8t(blk[8], blk[9], blk[10], blk[11], blk[12],
                                                                       blk[13],
                                                                       blk[14], blk[15]);
        }
    }


    for (size_t i = 0; i < 16; ++i) {
        for (size_t j = 0; j < 256; ++j) {
            ls_table_[i][j] = linear_table_64_[i][perm_s[j]];
            inv_sl_table_[i][j] = inv_linear_table_64_[i][inv_perm_s[j]];
        }
    }


    generate_keys(vec);
}

std::vector<std::string> KuznechikCipher::get_keys() {
    std::vector<std::string> res;
    for (auto &key: keys_) {
        res.push_back(utils::convert_uint_arr_to_str(key));
    }
    return res;
}

std::pair<uint64_t, uint64_t> KuznechikCipher::encode_block(std::vector<uint8_t> &blk) {
    auto first = utils::convert8uint8t(blk[0], blk[1], blk[2], blk[3],
                                       blk[4], blk[5], blk[6], blk[7]);
    auto second = utils::convert8uint8t(blk[8], blk[9], blk[10], blk[11],
                                        blk[12], blk[13], blk[14], blk[15]);
    for (size_t i = 0; i < 9; ++i) {
        first ^= keys_64_[i][0];
        second ^= keys_64_[i][1];
        make_operation_via_64_table(ls_table_, first, second);
    }

    first ^= keys_64_[9][0];
    second ^= keys_64_[9][1];
    return {first, second};
}

void KuznechikCipher::decode_block(uint64_t &first, uint64_t &second) {
    make_operation_via_64_table(inv_linear_table_64_, first, second);
    for (size_t i = 9; i > 0; --i) {
        first ^= inv_keys_64_[i][0];
        second ^= inv_keys_64_[i][1];
        if (i > 1) {
            make_operation_via_64_table(inv_sl_table_, first, second);
        }
    }

    first = utils::convert8uint8t(inv_perm_s[uint8_t(first >> 56)], inv_perm_s[uint8_t(first >> 48)],
                                  inv_perm_s[uint8_t(first >> 40)], inv_perm_s[uint8_t(first >> 32)],
                                  inv_perm_s[uint8_t(first >> 24)], inv_perm_s[uint8_t(first >> 16)],
                                  inv_perm_s[uint8_t(first >> 8)], inv_perm_s[uint8_t(first)]);

    second = utils::convert8uint8t(inv_perm_s[uint8_t(second >> 56)], inv_perm_s[uint8_t(second >> 48)],
                                   inv_perm_s[uint8_t(second >> 40)], inv_perm_s[uint8_t(second >> 32)],
                                   inv_perm_s[uint8_t(second >> 24)], inv_perm_s[uint8_t(second >> 16)],
                                   inv_perm_s[uint8_t(second >> 8)], inv_perm_s[uint8_t(second)]);


    first ^= inv_keys_64_[0][0];
    second ^= inv_keys_64_[0][1];
}

void KuznechikCipher::generate_keys(const std::vector<uint8_t> &key) {
    std::copy(key.begin(), key.begin() + 16, keys_[0].begin());
    std::copy(key.begin() + 16, key.end(), keys_[1].begin());

    std::vector<std::vector<uint8_t>> key_constants(32, std::vector<uint8_t>(16));
    for (size_t i = 0; i < key_constants.size(); ++i) {
        key_constants[i][15] = i + 1;
        key_constants[i] = do_linear_transform(key_constants[i]);
    }
    for (size_t i = 0; i < 4; ++i) {
        do_feistel(key_constants, i);
    }

    size_t iter = 0;
    for (auto &blk: keys_) {
        keys_64_[iter][0] = utils::convert8uint8t(blk[0], blk[1], blk[2], blk[3],
                                                  blk[4], blk[5], blk[6], blk[7]);
        keys_64_[iter][1] = utils::convert8uint8t(blk[8], blk[9], blk[10], blk[11],
                                                  blk[12], blk[13], blk[14], blk[15]);
        inv_keys_64_[iter] = keys_64_[iter];
        ++iter;
    }
    for (size_t i = 0; i < 10; ++i) {
        if (i != 0) {
            make_operation_via_64_table(inv_linear_table_64_, inv_keys_64_[i][0], inv_keys_64_[i][1]);
        }
        for (size_t j = 0; j < 8; ++j) {
            inv_keys_[i][7 - j] = uint8_t(inv_keys_64_[0][0] >> (8 * j));
            inv_keys_[i][15 - j] ^= uint8_t(inv_keys_64_[0][1] >> (8 * j));
        }

    }
}

void KuznechikCipher::do_feistel(const vector<vector<uint8_t>> &key_constants, size_t iter) {
    auto left = keys_[2 * iter];
    auto right = keys_[2 * iter + 1];
    for (size_t it = 0; it < 8; ++it) {
        vector<uint8_t> new_left(16);
        for (size_t index = 0; index < 16; ++index) {
            size_t constant_ind = iter * 8 + it;
            new_left[index] = perm_s[left[index] ^ key_constants[constant_ind][index]];
        }
        new_left = do_linear_transform(new_left);
        for (size_t index = 0; index < 16; ++index) {
            new_left[index] ^= right[index];
        }
        right = std::move(left);
        left = std::move(new_left);
    }
    keys_[2 * (iter + 1)] = std::move(left);
    keys_[2 * (iter + 1) + 1] = std::move(right);
}


std::vector<uint8_t> KuznechikCipher::do_linear_transform(const std::vector<uint8_t> &blk) {
    std::vector<uint8_t> res(16);
    for (size_t i = 0; i < 16; ++i) {
        for (size_t ind = 0; ind < 16; ++ind) {
            res[ind] ^= linear_table_[i][blk[i]][ind];
        }
    }
    return res;
}

void KuznechikCipher::make_operation_via_64_table(const vector<vector<vector<uint64_t>>> &table,
                                                  uint64_t &first, uint64_t &second) {
    auto f0 = uint8_t(first >> 56), f1 = uint8_t(first >> 48), f2 = uint8_t(first >> 40), f3 = uint8_t(
            first >> 32), f4 = uint8_t(first >> 24), f5 = uint8_t(first >> 16), f6 = uint8_t(
            first >> 8), f7 = uint8_t(first);
    auto s0 = uint8_t(second >> 56), s1 = uint8_t(second >> 48), s2 = uint8_t(second >> 40), s3 = uint8_t(
            second >> 32), s4 = uint8_t(second >> 24), s5 = uint8_t(second >> 16), s6 = uint8_t(
            second >> 8), s7 = uint8_t(second);

    first = table[0][f0][0] ^ table[1][f1][0] ^ table[2][f2][0] ^ table[3][f3][0] ^
            table[4][f4][0] ^ table[5][f5][0] ^ table[6][f6][0] ^ table[7][f7][0] ^
            table[8][s0][0] ^ table[9][s1][0] ^ table[10][s2][0] ^ table[11][s3][0] ^
            table[12][s4][0] ^ table[13][s5][0] ^ table[14][s6][0] ^ table[15][s7][0];


    second = table[0][f0][1] ^ table[1][f1][1] ^ table[2][f2][1] ^ table[3][f3][1] ^
             table[4][f4][1] ^ table[5][f5][1] ^ table[6][f6][1] ^ table[7][f7][1] ^
             table[8][s0][1] ^ table[9][s1][1] ^ table[10][s2][1] ^ table[11][s3][1] ^
             table[12][s4][1] ^ table[13][s5][1] ^ table[14][s6][1] ^ table[15][s7][1];
}
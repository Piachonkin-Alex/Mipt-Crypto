#pragma once

#include <vector>
#include <iostream>
#include <string>

namespace utils {
    inline int char2int(char input) {
        if (input >= '0' && input <= '9')
            return input - '0';
        if (input >= 'A' && input <= 'F')
            return input - 'A' + 10;
        if (input >= 'a' && input <= 'f')
            return input - 'a' + 10;
        throw std::invalid_argument("Invalid input string");
    }

    inline std::vector<uint8_t> hex2bin(const std::string &src) {
        if (src.size() % 2 != 0) {
            throw std::runtime_error("");
        }
        std::vector<uint8_t> res(src.size() / 2);
        for (size_t i = 0; i < src.size() / 2; ++i) {
            res[i] = char2int(src[2 * i]) * 16 + char2int(src[2 * i + 1]);
        }
        return res;
    }

    inline char uint_to_char(uint8_t val) {
        if (val < 10) {
            return '0' + val;
        } else {
            return 'a' + (val - 10);
        }
    }

    inline std::string convert_uint_arr_to_str(const std::vector<uint8_t> &arr) {
        std::string res(2 * arr.size(), 's');
        for (size_t i = 0; i < arr.size(); ++i) {
            uint8_t first = arr[i] / 16, second = arr[i] % 16;
            res[2 * i] = uint_to_char(first), res[2 * i + 1] = uint_to_char(second);
        }
        return res;
    }

    inline uint64_t convert8uint8t(uint8_t a1, uint8_t a2, uint8_t a3,
                                   uint8_t a4, uint8_t a5, uint8_t a6, uint8_t a7, uint8_t a8) {
        return (static_cast<uint64_t>(a1) << 56) + (static_cast<uint64_t>(a2) << 48) +
               (static_cast<uint64_t>(a3) << 40) +
               (static_cast<uint64_t>(a4) << 32) + (static_cast<uint64_t>(a5) << 24) +
               (static_cast<uint64_t>(a6) << 16) +
               (static_cast<uint64_t>(a7) << 8) + static_cast<uint64_t>(a8);
    }
}
/*
* library for xor strings.
* example use:

 -----------------------------------------------------------------------
#include <iostream>
#include "xor.h"
int main() {
    auto encrypted = elyXor("Hello World!");
    std::cout << encrypted.decrypt() << std::endl;

    std::cout << elyXor("Test String").decrypt() << std::endl;

    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
 -----------------------------------------------------------------------

* elyXor = xor process;
* .decrypt() = decrypt process;
*/
#ifndef XOR_H
#define XOR_H

#include <cstddef>
#include <type_traits>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <algorithm>

#ifdef XORLIB_KERNEL
#include <ntddk.h>
#define XOR_SLEEP(ms) KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)(&(LARGE_INTEGER){ -(LONGLONG)((ms)*10000) }))
#else
#include <windows.h>
#define XOR_SLEEP(ms) Sleep(ms)
#endif

namespace xorlib {

    template<typename T>
    using clean_t = typename std::remove_const_t<std::remove_reference_t<T>>;

    namespace detail {
        constexpr uint32_t crc32_char(uint32_t crc, char c) {
            crc ^= static_cast<uint8_t>(c);
            for (int k = 0; k < 8; ++k)
                crc = (crc >> 1) ^ (0xEDB88320u * (crc & 1));
            return crc;
        }

        constexpr uint32_t crc32_str(const char* str, std::size_t len) {
            uint32_t crc = 0xFFFFFFFF;
            for (std::size_t i = 0; i < len; ++i)
                crc = crc32_char(crc, str[i]);
            return ~crc;
        }

        constexpr uint32_t base_hash = crc32_str(__TIME__, 8);
        constexpr uint32_t hash_mix(uint32_t seed, int counter) {
            return (seed ^ (counter * 2654435761u)) + ((seed << 5) | (seed >> 27));
        }

        template<int Counter>
        struct Keys {
            static constexpr uint32_t base = hash_mix(base_hash, Counter);
            static constexpr char K1 = static_cast<char>((base >> 0) & 0x7F);
            static constexpr char K2 = static_cast<char>((base >> 8) & 0x7F);
            static constexpr char K3 = static_cast<char>((base >> 16) & 0x7F);
            static constexpr char K4 = static_cast<char>((base >> 24) & 0x7F);
            static constexpr char K5 = static_cast<char>((base ^ 0xA5A5A5A5) & 0x7F);
            static constexpr char K6 = static_cast<char>((base ^ 0x5A5A5A5A) & 0x7F);
            static constexpr char K7 = static_cast<char>((base ^ 0x3C3C3C3C) & 0x7F);
        };
    }

    template <int _size, char K1, char K2, char K3, char K4, char K5, char K6, char K7, typename T>
    class XorString {
    public:
        __forceinline constexpr XorString(T* data) {
            crypt(data);
        }

        __forceinline T* get() {
            return decrypt();
        }

        __forceinline T* encrypt() {
            if (!isEncrypted()) crypt(_storage);
            return _storage;
        }

        __forceinline T* decrypt() {
            if (isEncrypted()) crypt(_storage);
            return _storage;
        }

        __forceinline bool isEncrypted() const {
            return _storage[_size - 1] != 0;
        }

    private:
        __forceinline constexpr void crypt(T* data) {
            for (int i = 0; i < _size; ++i) {
                char k1 = K1;
                k1 ^= (i * K2);
                k1 += (i % 5) * K3;
                k1 = (k1 & 0x5A) | ((~k1) & 0xA5);
                k1 ^= ((i << 2) ^ K4);
                k1 += (K5 ^ (i * 7));
                k1 = ((k1 << 3) | (k1 >> 5)) ^ 0x3C;

                T c1 = data[i] ^ static_cast<T>(static_cast<unsigned char>(k1));
                c1 = (c1 ^ (static_cast<T>(static_cast<unsigned char>(k1 >> 1)))) + (static_cast<T>(static_cast<unsigned char>(k1 & 0x1F)));
                c1 = (c1 ^ (static_cast<T>(static_cast<unsigned char>(k1 << 1)))) - (static_cast<T>(static_cast<unsigned char>(k1 & 0x0F)));

                char k2 = K6;
                k2 ^= (i * K7);
                k2 += (i % 7) * K3;
                k2 = (k2 & 0x3C) | ((~k2) & 0xC3);
                k2 ^= ((i << 3) ^ K5);
                k2 += (K4 ^ (i * 5));
                k2 = ((k2 << 2) | (k2 >> 6)) ^ 0x5A;

                T c2 = c1 ^ static_cast<T>(static_cast<unsigned char>(k2));
                c2 = (c2 ^ (static_cast<T>(static_cast<unsigned char>(k2 >> 2)))) + (static_cast<T>(static_cast<unsigned char>(k2 & 0x2F)));
                c2 = (c2 ^ (static_cast<T>(static_cast<unsigned char>(k2 << 2)))) - (static_cast<T>(static_cast<unsigned char>(k2 & 0x1F)));

                char k3 = K7;
                k3 ^= (i * K6);
                k3 += (i % 3) * K2;
                k3 = (k3 & 0xAA) | ((~k3) & 0x55);
                k3 ^= ((i << 1) ^ K3);
                k3 += (K1 ^ (i * 3));
                k3 = ((k3 << 4) | (k3 >> 4)) ^ 0xA5;

                T c3 = c2 ^ static_cast<T>(static_cast<unsigned char>(k3));
                c3 = (c3 ^ (static_cast<T>(static_cast<unsigned char>(k3 >> 3)))) + (static_cast<T>(static_cast<unsigned char>(k3 & 0x3F)));
                c3 = (c3 ^ (static_cast<T>(static_cast<unsigned char>(k3 << 3)))) - (static_cast<T>(static_cast<unsigned char>(k3 & 0x2F)));

                _storage[i] = c3;
            }
        }

        T _storage[_size]{};
    };

    template<typename T>
    class AutoXorGuard {
    public:
        explicit AutoXorGuard(T& xorStr) : ref(xorStr) {
            ref.decrypt();
        }

        ~AutoXorGuard() {
            auto* data = ref.get();
            const std::size_t len = sizeof(*data) * (sizeof(data) / sizeof(*data));

            std::srand(static_cast<unsigned>(std::time(nullptr)));
            const char randKey = static_cast<char>(std::rand() % 0x7F + 1);

            for (std::size_t i = 0; i < len; ++i)
                data[i] ^= static_cast<T>(static_cast<unsigned char>(randKey));

            volatile char* p = reinterpret_cast<volatile char*>(data);
            for (std::size_t i = 0; i < len * sizeof(T); ++i)
                p[i] = 0;
        }

    private:
        T& ref;
    };
}

#define elyXor(str) elyXor_key(str, __COUNTER__)
#define elyXor_key(str, ID) [](){ \
    constexpr static auto crypted = xorlib::XorString< \
        sizeof(str)/sizeof(str[0]), \
        xorlib::detail::Keys<ID>::K1, \
        xorlib::detail::Keys<ID>::K2, \
        xorlib::detail::Keys<ID>::K3, \
        xorlib::detail::Keys<ID>::K4, \
        xorlib::detail::Keys<ID>::K5, \
        xorlib::detail::Keys<ID>::K6, \
        xorlib::detail::Keys<ID>::K7, \
        xorlib::clean_t<decltype(str[0])> >((xorlib::clean_t<decltype(str[0])>*)str); \
    return crypted; \
}()

#define elyXorW(str) elyXorW_key(str, __COUNTER__)
#define elyXorW_key(str, ID) [](){ \
    constexpr static auto crypted = xorlib::XorString< \
        sizeof(str)/sizeof(str[0]), \
        xorlib::detail::Keys<ID>::K1, \
        xorlib::detail::Keys<ID>::K2, \
        xorlib::detail::Keys<ID>::K3, \
        xorlib::detail::Keys<ID>::K4, \
        xorlib::detail::Keys<ID>::K5, \
        xorlib::detail::Keys<ID>::K6, \
        xorlib::detail::Keys<ID>::K7, \
        wchar_t >((wchar_t*)str); \
    return crypted; \
}()

#endif // XOR_H

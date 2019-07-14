#pragma once

#include <boost/lexical_cast.hpp>


namespace tz {
    using namespace std;

    template <class F, class T>
    inline bool try_cast(const F &from, T &to) {
        try {
            to = boost::lexical_cast<T>(from);
            return true;
        } catch (boost::bad_lexical_cast &) {
            return false;
        }
    }

    // specializations for 8bit int
    template <class T>
    inline bool try_cast(const uint8_t &from, T &to) {
        return try_cast(uint32_t(from), to);
    }

    template <class T>
    inline bool try_cast(const int8_t &from, T &to) {
        return try_cast(int32_t(from), to);
    }

    template <class F>
    inline bool try_cast(const F &from, uint8_t &to) {
        uint32_t u32 = 0;
        if (!try_cast(from, u32)) {
            return false;
        }
        if (u32 > 0xff) {
            return false;
        }

        to = u32;
        return true;
    }

    template <class F>
    inline bool try_cast(const F &from, int8_t &to) {
        int32_t i32 = 0;
        if (!try_cast(from, i32)) {
            return false;
        }
        if (i32 > 127 || i32 < -128) {
            return false;
        }

        to = i32;
        return true;
    }

    template <class F, class T>
    inline T cast(const F &from, const T &def) {
        T value;
        if (try_cast(from, value)) {
            return value;
        } else {
            return def;
        }
    }

    template <class MapType, class KeyType, class T>
    inline T map_get(const MapType &mapping, const KeyType &key, const T &def)
    {
        typename MapType::const_iterator it = mapping.find(key);
        if (it == mapping.end()) {
            return def;
        }
        return cast(it->second, def);
    }

    template <class MapType, class KeyType>
    inline const typename MapType::value_type::second_type &
    map_get(const MapType &mapping, const KeyType &key)
    {
        typename MapType::const_iterator it = mapping.find(key);
        assert(it != mapping.end());
        return it->second;
    }

}   // namespace tz

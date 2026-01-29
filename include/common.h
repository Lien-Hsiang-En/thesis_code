#ifndef TC_REDIRECT_COMMON_H
#define TC_REDIRECT_COMMON_H

#include <stdint.h>

struct stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t redirected;
    uint64_t passed;
};

#endif

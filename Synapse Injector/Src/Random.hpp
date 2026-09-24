#pragma once

#import <Foundation/Foundation.h>
#import <stdint.h>

// Since Objective-C doesn't have constexpr/templates, we use runtime functions
// and macros. The __COUNTER__ trick is replaced by a runtime counter that is
// still unique per call site via macro expansion.

static inline uint64_t time_from_string(const char *str, int offset) {
    return ((uint64_t)(str[offset] - '0') * 10) +
           (uint64_t)(str[offset + 1] - '0');
}

// Runtime seed generator. Because Obj-C has no constexpr, we compute at runtime.
// We keep the same hashing logic as the original.
static inline uint64_t get_seed_runtime(uint64_t counter) {
    const char *t = __TIME__;
    uint64_t nt = (time_from_string(t, 0) * 60 * 60 +
                   time_from_string(t, 3) * 60 +
                   time_from_string(t, 6));

    uint64_t hashedValue = 3074457345618258791ULL;
    for (int i = 0; i < (int)sizeof(uint64_t); i++) {
        hashedValue += nt & ((1ULL << i) + counter);
        hashedValue *= 3074457345618258799ULL;
    }
    return hashedValue;
}

static const uint64_t lce_a = 1273686654176231872ULL;
static const uint64_t lce_c = 1278361726378617232ULL;
static const uint64_t lce_m = 187236981273ULL;

static inline uint64_t uniform_distribution(uint64_t *previous) {
    *previous = ((lce_a * (*previous) + lce_c) % lce_m);
    return *previous;
}

static inline double uniform_distribution_n(uint64_t *previous) {
    uint64_t dst = uniform_distribution(previous);
    return (double)dst / (double)lce_m;
}

// Generic scalar generator (one value). Replaces the templated array version
// for the common case used by RAND_NUM / gen_rand32 / gen_rand64.
static inline double uniform_distribution_scalar(double min, double max, uint64_t counter) {
    uint64_t previous = get_seed_runtime(counter);
    return uniform_distribution_n(&previous) * (max - min) + min;
}

// A small runtime counter so each macro expansion gets a unique seed.
// Note: this differs from __COUNTER__ (compile-time) but preserves the
// "different seed per call site" intent.
static inline uint64_t next_rand_counter(void) {
    static uint64_t counter = 0;
    return counter++;
}

// Macros – API compatible with the original.
#define RAND_NUM(mi, ma) \
    ((__typeof__(ma))uniform_distribution_scalar((double)(mi), (double)(ma), next_rand_counter()))

#define gen_rand32 \
    ((uint32_t)uniform_distribution_scalar(0.0, (double)UINT32_MAX, next_rand_counter()))

#define gen_rand64 \
    ((uint64_t)uniform_distribution_scalar(0.0, (double)UINT64_MAX, next_rand_counter()))

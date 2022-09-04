#pragma once

#include <stdio.h>

class Tls {
private:
    static int calloc_self_test( int verbose );
    static int test_snprintf( size_t n, const char *ref_buf, int ref_ret );
    static int run_test_snprintf( void );

    static int mbedtls_entropy_self_test_wrapper( int verbose );
    static int mbedtls_memory_buffer_alloc_free_and_self_test( int verbose );

    typedef struct {
        const char *name;
        int ( *function )( int );
    } selftest_t;

public:
    static void test(void);
};

#include <check.h>

#ifndef RUN_TEST
#define RUN_TEST(fn)                            \
    int main (void)                             \
    {                                           \
        Suite *s = suite_create(#fn);           \
                                                \
        TCase *tc = tcase_create(#fn);          \
        tcase_add_test(tc, (fn));               \
        suite_add_tcase(s, tc);                 \
                                                \
        SRunner *sr = srunner_create(s);        \
        srunner_run_all(sr, CK_NORMAL);         \
        int failed = srunner_ntests_failed(sr); \
        srunner_free(sr);                       \
                                                \
        return failed ? 1 : 0;                  \
    }
#endif

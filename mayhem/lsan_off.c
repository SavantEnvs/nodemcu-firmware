/* Disable LeakSanitizer (leaks are not the bug class fuzzed here); ASan and UBSan stay active. */
int __lsan_is_turned_off(void) { return 1; }

/* Original Pear finite native memory-owner controls. MIT-licensed.
 * The wire structures are defined only by the selected Wine source header. */
#ifndef PEAR_MEMORY_FIXTURE_SUITE_H
#define PEAR_MEMORY_FIXTURE_SUITE_H
#include "wine/pear_fex_memory.h"

struct pear_memory_fixture_platform {
    const char *scope;
    uint64_t owner_pid;
    int checked_ec;
    uint32_t role;
    uint32_t (*call)(const struct pear_fex_memory_request *, struct pear_fex_memory_response *);
    uint32_t (*poll)(uint64_t);
    int (*observe)(uint64_t address, uint64_t bytes, uint32_t protection);
    int (*execute)(uint64_t address, unsigned int expected);
};
/* The supervisor has already released the platform's admission handshake.
 * This function never initializes FEX or creates a guest process. */
int pear_memory_fixture_suite(const struct pear_memory_fixture_platform *);
#endif

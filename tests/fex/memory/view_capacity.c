/* SPDX-License-Identifier: MIT
 * Exact selected Wine counter with substituted fixed view storage. No Wine
 * execution, VM allocation, owner mutation or engine initialization. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
struct file_view { struct file_view *next; unsigned char padding[72]; };
static struct file_view storage[2048], *view_block_start, *view_block_end, *next_free_view;
static const uint64_t view_block_size=1048576;
#define PEAR_FEX_MEMORY_OBSERVATION_SLOTS 1024
#define min(a,b) ((a)<(b)?(a):(b))
#include "selected_view_counter.inc"
int main(void) {
    uint64_t count=99;
    assert(pear_fex_available_views(&count) && !count);
    view_block_start=view_block_end=storage;
    assert(!pear_fex_available_views(&count) && !count);
    view_block_end=storage+1;
    assert(!pear_fex_available_views(&count) && count==1);
    view_block_end=storage+2;
    assert(!pear_fex_available_views(&count) && count==2);
    view_block_end=storage;
    next_free_view=storage+100; storage[100].next=NULL;
    assert(!pear_fex_available_views(&count) && count==1);
    storage[100].next=storage+101;storage[101].next=NULL;
    assert(!pear_fex_available_views(&count) && count==2);
    storage[101].next=storage+100;
    assert(pear_fex_available_views(&count) && !count);
    next_free_view=NULL;view_block_end=storage+2048;
    assert(!pear_fex_available_views(&count) && count==1024);
    view_block_start=storage+1;view_block_end=storage;
    assert(pear_fex_available_views(&count) && !count);
    puts("PASS: unavailable, exhausted, one/two reusable records, cyclic list, saturation and invalid bounds");
}

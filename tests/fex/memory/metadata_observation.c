/* SPDX-License-Identifier: MIT
 * Actual owner dispatch with substituted non-executing backing callbacks.
 * This is protocol coverage, not Wine mapping or FEX initialization evidence. */
#include "pear_fex_memory_private.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
static unsigned observations, queries, mutations;
static int failure;
static uint32_t selected_role = PEAR_FEX_ROLE_NATIVE;
static int initialize(struct pear_fex_memory_backing *b, struct pear_fex_memory_error *e) {
    (void)e; b->owner_pid=getpid(); b->private_base=65536; b->shared_offset=65536;
    b->dispatcher_offset=b->shared_offset+PEAR_FEX_MEMORY_SHARED_BYTES+PEAR_FEX_MEMORY_SEPARATOR_BYTES;
    b->capabilities=3; return 0;
}
static int query(uint64_t a,uint64_t b,uint32_t c,struct pear_fex_memory_error *e) {
    (void)a;(void)b;(void)c;(void)e;++queries;return 0;
}
static int protect(uint64_t a,uint64_t b,uint32_t c,struct pear_fex_memory_error *e) {
    (void)a;(void)b;(void)c;(void)e;++mutations;return 1;
}
static int view(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint32_t e,uint32_t f,int g,struct pear_fex_memory_error *h) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;++mutations;return 1;
}
static int ec(uint64_t a,uint64_t b,int publish,struct pear_fex_memory_error *e) {
    (void)a;(void)b;(void)publish;(void)e;++mutations;return 1;
}
static int role(uint32_t v) {return v==selected_role;}
static int entry(uint64_t a,uint64_t b,uint64_t c,uint32_t d,uint32_t e) {
    (void)a;(void)b;(void)c;(void)d;(void)e;++mutations;return 0;
}
static int observe(struct pear_fex_memory_metadata *m,struct pear_fex_memory_error *e) {
    ++observations;
    if(failure){e->domain=PEAR_FEX_ERROR_ERRNO;e->code=EIO;return 1;}
    m->mapping_bytes=1588985856;m->baseline_mapping_bytes=1050935296;m->page_bytes=4096;
    m->leaf_coverage_bytes=UINT64_C(4294967296);m->leaf_backing_bytes=1048576;m->baseline_leaves=1;
    m->view_block_bytes=1048576;m->view_record_bytes=80;m->available_view_slots=1024;
    m->fixed_native_bytes=5164;return 0;
}
static void refused(struct pear_fex_memory_request q,uint32_t expected) {
    struct pear_fex_memory_response r,zero={0};memset(&r,0xa5,sizeof(r));
    assert(pear_fex_memory_dispatch(&q,&r)==expected);
    zero.version=3;zero.size=128;zero.status=expected;
    if(expected==PEAR_FEX_NATIVE_FAILURE){zero.native_error_domain=PEAR_FEX_ERROR_ERRNO;zero.native_error_code=EIO;}
    assert(!memcmp(&r,&zero,sizeof(r)));
}
int main(void) {
    struct pear_fex_memory_request q={0},bad;struct pear_fex_memory_response raw;
    struct pear_fex_memory_metadata m;struct pear_fex_memory_error error;
    struct pear_fex_memory_backend b={initialize,query,protect,ec,view,role,entry,observe};
    q.version=3;q.size=128;q.opcode=PEAR_FEX_OBSERVE_METADATA;q.owner_pid=getpid();q.ec_role=PEAR_FEX_ROLE_NATIVE;
    refused(q,PEAR_FEX_UNAVAILABLE);assert(!observations);
    assert(pear_fex_memory_initialize(&b,&error)==0);assert(queries==2);
    for(unsigned v=0;v<5;++v)if(v!=3){bad=q;bad.version=v;refused(bad,PEAR_FEX_VERSION_MISMATCH);}
    for(unsigned r=0;r<2;++r){bad=q;bad.ec_role=r;refused(bad,PEAR_FEX_UNAVAILABLE);}
    bad=q;bad.owner_pid++;refused(bad,PEAR_FEX_STALE_IDENTITY);
    const size_t offsets[]={12,24,32,40,48,56,64,72,80,88,96,104,108,112,120};
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){bad=q;((unsigned char *)&bad)[offsets[i]]=1;refused(bad,PEAR_FEX_INVALID_REQUEST);}
    assert(!observations);assert(pear_fex_memory_dispatch(&q,&raw)==0);memcpy(&m,&raw,sizeof(m));
    assert(m.version==3&&m.owner_pid==(uint64_t)getpid()&&m.available_view_slots==1024&&m.fixed_native_bytes>5164);
    assert(!m.status&&!m.reserved0&&!m.reserved1);
    failure=1;refused(q,PEAR_FEX_NATIVE_FAILURE);assert(observations==2&&queries==2&&!mutations);
    failure=0;assert(pear_fex_memory_dispatch(&q,&raw)==0);assert(observations==3&&queries==2&&!mutations);
    selected_role=PEAR_FEX_ROLE_ARM64EC;
    refused(q,PEAR_FEX_UNAVAILABLE);assert(observations==3);
    q.ec_role=PEAR_FEX_ROLE_ARM64EC;
    assert(pear_fex_memory_dispatch(&q,&raw)==0);memcpy(&m,&raw,sizeof(m));
    assert(m.owner_pid==(uint64_t)getpid()&&!m.status&&observations==4&&!mutations);
    selected_role=PEAR_FEX_ROLE_NATIVE;
    refused(q,PEAR_FEX_UNAVAILABLE);assert(observations==4&&queries==2&&!mutations);
    puts("PASS: read-only metadata, backend-selected native/EC roles, closed fields and error retention");return 0;
}

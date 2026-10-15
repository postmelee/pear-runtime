#pragma once
#include <stdint.h>
#include <stdio.h>
// Private diagnostic payload, not the Wine/FEX request ABI.
struct PearAbortRecord {
  uint64_t pid;
  uint64_t tid;
  uint64_t guard;
  uint64_t call;
  uint64_t life;
  uint64_t allocation;
  uint64_t generation;
  uint64_t extent;
  uint64_t size;
  uint64_t epoch;
  uint64_t expected;
  uint64_t aclass;
  uint64_t role;
  uint64_t continuation;
  uint64_t before_epoch;
  uint64_t before_state;
  uint64_t begin_state;
  uint64_t status;
  uint64_t domain;
  int64_t code;
  uint64_t executor;
  uint64_t bridge;
  uint64_t validated;
  uint64_t reason;
  uint64_t previous_known;
  uint64_t previous;
};
static inline int pear_abort_format(char *buffer, size_t size, unsigned side, const struct PearAbortRecord *d) {
  if (side==1) return snprintf(buffer,size,"PEAR_ABORT1 side=core pid=%llu tid=%llu guard=%llu call=%llu life=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu before_epoch=%llu before_state=%llu begin_state=%llu status=%llu domain=%llu code=%lld\n",(unsigned long long)d->pid,(unsigned long long)d->tid,(unsigned long long)d->guard,(unsigned long long)d->call,(unsigned long long)d->life,(unsigned long long)d->allocation,(unsigned long long)d->generation,(unsigned long long)d->extent,(unsigned long long)d->size,(unsigned long long)d->epoch,(unsigned long long)d->expected,(unsigned long long)d->aclass,(unsigned long long)d->role,(unsigned long long)d->continuation,(unsigned long long)d->before_epoch,(unsigned long long)d->before_state,(unsigned long long)d->begin_state,(unsigned long long)d->status,(unsigned long long)d->domain,(long long)d->code);
  if (side==2) return snprintf(buffer,size,"PEAR_ABORT1 side=source pid=%llu tid=%llu guard=%llu call=%llu life=%llu executor=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu bridge=%llu validated=%llu status=%llu domain=%llu code=%lld\n",(unsigned long long)d->pid,(unsigned long long)d->tid,(unsigned long long)d->guard,(unsigned long long)d->call,(unsigned long long)d->life,(unsigned long long)d->executor,(unsigned long long)d->allocation,(unsigned long long)d->generation,(unsigned long long)d->extent,(unsigned long long)d->size,(unsigned long long)d->epoch,(unsigned long long)d->expected,(unsigned long long)d->aclass,(unsigned long long)d->role,(unsigned long long)d->continuation,(unsigned long long)d->bridge,(unsigned long long)d->validated,(unsigned long long)d->status,(unsigned long long)d->domain,(long long)d->code);
  if (side==3) return snprintf(buffer,size,"PEAR_ABORT1 side=owner pid=%llu executor=%llu allocation=%llu generation=%llu extent=%llu size=%llu epoch=%llu expected=%llu aclass=%llu role=%llu continuation=%llu reason=%llu previous_known=%llu previous=%llu status=%llu domain=%llu code=%lld\n",(unsigned long long)d->pid,(unsigned long long)d->executor,(unsigned long long)d->allocation,(unsigned long long)d->generation,(unsigned long long)d->extent,(unsigned long long)d->size,(unsigned long long)d->epoch,(unsigned long long)d->expected,(unsigned long long)d->aclass,(unsigned long long)d->role,(unsigned long long)d->continuation,(unsigned long long)d->reason,(unsigned long long)d->previous_known,(unsigned long long)d->previous,(unsigned long long)d->status,(unsigned long long)d->domain,(long long)d->code);
  return -1;
}
#ifdef __cplusplus
extern "C" bool PearAbortEnabled();
extern "C" void PearAbortEmit(unsigned, const PearAbortRecord*);
extern "C" uint64_t PearAbortBegin(const PearAbortRecord*);
#endif

// SPDX-License-Identifier: MIT
// The included body is extracted unchanged from the selected FEX source.
#include <cassert>
#include <cstdint>
#include <cstdio>
#include "wine/pear_fex_memory.h"
struct Result { uint32_t Status; uint32_t ErrorDomain; int32_t ErrorCode; explicit operator bool()const{return Status==0;} };
static Result Refuse(uint32_t s=PEAR_FEX_UNAVAILABLE){return {s,0,0};}
#include "selected_metadata_budget.inc"
int main(){
  pear_fex_memory_metadata m{};m.version=3;m.size=128;m.owner_pid=7;m.mapping_bytes=1588985856;
  m.baseline_mapping_bytes=1050935296;m.page_bytes=4096;m.leaf_coverage_bytes=UINT64_C(4294967296);
  m.leaf_backing_bytes=1048576;m.baseline_leaves=1;m.view_block_bytes=1048576;m.view_record_bytes=80;
  m.available_view_slots=1024;m.fixed_native_bytes=108564;uint64_t total=999;
  assert(AssessMetadataBudget(m,7,64,120000,total)&&total==242880);
  auto refuse=[&](auto value,uint64_t views,uint64_t bytes){total=999;assert(!AssessMetadataBudget(value,7,views,bytes,total)&&!total);};
  auto n=m;n.additional_leaves=1;refuse(n,64,0);
  n=m;n.available_view_slots=63;refuse(n,64,0);
  n=m;n.available_view_slots=0;refuse(n,1,0);
  n=m;n.available_view_slots=UINT64_MAX;refuse(n,64,0);
  n=m;n.fixed_native_bytes=UINT64_MAX;refuse(n,64,0);
  n=m;n.leaf_backing_bytes=UINT64_MAX;refuse(n,64,0);
  n=m;n.owner_pid=8;refuse(n,64,0);
  n=m;n.status=PEAR_FEX_NATIVE_FAILURE;n.native_error_domain=1;n.native_error_code=5;refuse(n,64,0);
  n=m;n.version=2;refuse(n,64,0);n=m;n.reserved1=1;refuse(n,64,0);
  refuse(m,0,0);refuse(m,1025,0);refuse(m,64,UINT64_MAX);refuse(m,64,262144);
  assert(AssessMetadataBudget(m,7,1024,139264,total)&&total==262144);
  refuse(m,1024,139265);
  puts("PASS: actual classifier rejects additional blocks, insufficient capacity, overflow and malformed facts; exact ceiling accepted");
}

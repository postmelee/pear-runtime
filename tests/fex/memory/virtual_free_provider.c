/* SPDX-License-Identifier: MIT
 * Original Pear finite ordinary-ARM64 Wine allocation-provider diagnostic.
 * No FEX initialization, executable memory, translated guest or game data. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
static char output[384];static unsigned length;
static void text(const char *s) { while(*s && length<sizeof(output)) output[length++]=*s++; }
static void number(uint32_t n) { char b[10];unsigned c=0;do { b[c++]=(char)('0'+n%10);n/=10; }while(n);while(c && length<sizeof(output)) output[length++]=b[--c]; }
static void result(unsigned cycle,unsigned step,DWORD error,DWORD refused,DWORD cleanup) {
 DWORD written=0;length=0;text("{\"record_kind\":\"pear_virtual_free_provider\",\"cycle\":");number(cycle);
 text(",\"step\":");number(step);text(",\"error\":");number(error);text(",\"refusal_error\":");number(refused);
 text(",\"cleanup_error\":");number(cleanup);text("}\n");
 if(length==sizeof(output) || !WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,length,&written,NULL) || written!=length) ExitProcess(90);
}
void mainCRTStartup(void) {
 for(unsigned cycle=0;cycle<32;cycle++) {
  SIZE_T bytes=cycle%2?16384:4096;void *p=NULL;unsigned step=1;DWORD error=0,refused=0,cleanup=0;MEMORY_BASIC_INFORMATION info;
  p=VirtualAlloc(NULL,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!p) { error=GetLastError();goto failed; }
  step=2;if(!VirtualQuery(p,&info,sizeof(info))) { error=GetLastError();goto failed; }
  if(info.State!=MEM_COMMIT || info.AllocationBase!=p || info.Protect!=PAGE_READWRITE) goto failed;
  ((volatile unsigned char*)p)[0]=0x31;((volatile unsigned char*)p)[bytes-1]=0x72;
  step=3;SetLastError(0);if(VirtualFree(p,bytes,MEM_RELEASE)) { p=NULL;goto failed; }refused=GetLastError();if(!refused) goto failed;
  step=4;if(!VirtualQuery(p,&info,sizeof(info))) { error=GetLastError();goto failed; }
  if(info.State!=MEM_COMMIT || info.AllocationBase!=p || ((volatile unsigned char*)p)[0]!=0x31 || ((volatile unsigned char*)p)[bytes-1]!=0x72) goto failed;
  step=5;if(!VirtualFree(p,0,MEM_RELEASE)) { error=GetLastError();goto failed; }
  { void *old=p;p=NULL;step=6;if(!VirtualQuery(old,&info,sizeof(info))) { error=GetLastError();goto failed; }
    if(info.State!=MEM_FREE || info.AllocationBase!=NULL) goto failed; }
  result(cycle,0,0,refused,0);continue;
 failed:
  if(p && !VirtualFree(p,0,MEM_RELEASE)) cleanup=GetLastError();
  result(cycle,step,error,refused,cleanup);ExitProcess(1);
 }
 ExitProcess(0);
}

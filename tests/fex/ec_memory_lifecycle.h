// SPDX-License-Identifier: MIT
// Original Pear finite probe, included only by the recorded development build.
// Invoke after actual ARM64EC ThreadInit publishes its genuine source binding.
// This is a memory-owner test; it never executes its placeholder instructions.
static NTSTATUS PearRunECMemoryLifecycle() {
  namespace M = FEXCore::Utils::PearFEXMemory;
  unsigned Checks {};
  auto Check = [&](bool Good) {
    ++Checks;
    if (!Good) PearInitCheckpoint("ECMemory.refused", STATUS_UNSUCCESSFUL, 0, Checks);
    return Good;
  };
  auto Bit = [](uint8_t* Address) -> int {
    const auto Bitmap = *reinterpret_cast<uint8_t**>(reinterpret_cast<uintptr_t>(NtCurrentTeb()->ProcessEnvironmentBlock) + 0x368);
    if (!Bitmap) return -1;
    const auto Page = reinterpret_cast<uintptr_t>(Address) >> 12;
    MEMORY_BASIC_INFORMATION Info {}; SIZE_T Returned {};
    auto* Byte = Bitmap + Page / 8;
    if (NtQueryVirtualMemory(NtCurrentProcess(), Byte, MemoryBasicInformation, &Info, sizeof(Info), &Returned) ||
        Returned != sizeof(Info) || Info.State != MEM_COMMIT || (Info.Protect != PAGE_READWRITE && Info.Protect != PAGE_READONLY)) return -1;
    return (*Byte >> (Page & 7)) & 1;
  };
  auto Publish = [&](M::Allocation& A) {
    M::WriteGuard Write(A, 0, 16384);
    if (!Check(!!Write)) return false;
    memset(Write.Data(), 0, 16384);
    const uint32_t Return = 0xd65f03c0;
    memcpy(Write.Data(), &Return, sizeof(Return));
    if (!Check(!!Write.Publish())) return false;
    return Check(Bit(A.Base) == 1) && Check(!!M::Query(A));
  };
  pear_fex_memory_metadata Before {}, After {};
  if (!Check(!!M::ObserveMetadata(Before))) return STATUS_UNSUCCESSFUL;
  auto A = M::Reserve(16384, PEAR_FEX_CLASS_DISPATCHER, PEAR_FEX_ROLE_ARM64EC);
  auto B = M::Reserve(16384, PEAR_FEX_CLASS_DISPATCHER, PEAR_FEX_ROLE_ARM64EC);
  if (!Check(!!A && !!B) || !Publish(A) || !Publish(B)) return STATUS_UNSUCCESSFUL;
  auto* OriginalBase = A.Base;
  const auto OriginalID = A.Token.allocation_id, OriginalGeneration = A.Token.generation;
  // Adjacent extents share one real bitmap backing page; clear only A's bits.
  if (!Check(((reinterpret_cast<uintptr_t>(A.Base) >> 15) >> 12) ==
             ((reinterpret_cast<uintptr_t>(B.Base) >> 15) >> 12))) return STATUS_UNSUCCESSFUL;
  if (!Check(!!M::Enter(A, 0)) || !Check(M::HasManagedActive(A))) return STATUS_UNSUCCESSFUL;
  uint64_t Pin {};
  if (!Check(!!M::Handoff(A, 0, Pin)) || !Check(Pin != 0)) return STATUS_UNSUCCESSFUL;
  const auto HeldRetire = M::Retire(A);
  if (!Check(HeldRetire.Status == PEAR_FEX_UNAVAILABLE && !HeldRetire.ErrorDomain) ||
      !Check(Bit(A.Base) == 1 && Bit(B.Base) == 1) || !Check(!!M::Query(A))) return STATUS_UNSUCCESSFUL;
  if (!Check(!!M::Unpin(A, Pin, A.Token.write_epoch))) return STATUS_UNSUCCESSFUL;
  auto Stale = A;
  if (!Check(!!M::Retire(A)) || !Check(Bit(OriginalBase) == 0 && Bit(B.Base) == 1)) return STATUS_UNSUCCESSFUL;
  if (!Check(M::Query(Stale).Status == PEAR_FEX_STALE_IDENTITY)) return STATUS_UNSUCCESSFUL;
  auto Reused = M::Reserve(16384, PEAR_FEX_CLASS_DISPATCHER, PEAR_FEX_ROLE_ARM64EC);
  if (!Check(!!Reused && Reused.Token.extent_offset == Stale.Token.extent_offset &&
             (Reused.Token.allocation_id != OriginalID || Reused.Token.generation != OriginalGeneration))) return STATUS_UNSUCCESSFUL;
  if (!Publish(Reused) || !Check(M::Enter(Stale, 0).Status == PEAR_FEX_STALE_IDENTITY)) return STATUS_UNSUCCESSFUL;
  if (!Check(!!M::Enter(Reused, 0)) || !Check(!!M::Exit(Reused))) return STATUS_UNSUCCESSFUL;
  auto* PeerBase = B.Base;
  if (!Check(!!M::Retire(Reused)) || !Check(Bit(OriginalBase) == 0 && Bit(PeerBase) == 1) ||
      !Check(!!M::Retire(B)) || !Check(Bit(PeerBase) == 0)) return STATUS_UNSUCCESSFUL;
  if (!Check(!!M::ObserveMetadata(After)) || !Check(After.owner_pid == Before.owner_pid &&
      After.mapping_bytes == Before.mapping_bytes && After.available_view_slots == Before.available_view_slots)) return STATUS_UNSUCCESSFUL;
  // A shared-code extent is partially published and retains its final guard.
  auto Shared = M::Reserve(16777216, PEAR_FEX_CLASS_SHARED, PEAR_FEX_ROLE_ARM64EC);
  if (!Check(!!Shared)) return STATUS_UNSUCCESSFUL;
  {
    M::WriteGuard Write(Shared, 0, 4096);
    if (!Check(!!Write)) return STATUS_UNSUCCESSFUL;
    memset(Write.Data(), 0, 4096);
    if (!Check(!!Write.Publish())) return STATUS_UNSUCCESSFUL;
  }
  auto* SharedBase = Shared.Base;
  PearInitCheckpoint("ECMemory.shared-bits", 0, Bit(SharedBase), Bit(SharedBase + 16777216 - 4096));
  if (!Check(Bit(SharedBase) == 1 && Bit(SharedBase + 16777216 - 4096) == 0) ||
      !Check(M::Query(Shared).Status == PEAR_FEX_UNAVAILABLE) ||
      !Check(!!M::Enter(Shared, 0)) || !Check(!!M::Exit(Shared)) ||
      !Check(!!M::Retire(Shared)) || !Check(Bit(SharedBase) == 0)) return STATUS_UNSUCCESSFUL;
  // Count writable bitmap backing separately from its large lazy read-only
  // reservation. VirtualQuery does not measure resident physical memory.
  const auto Bitmap = reinterpret_cast<uintptr_t>(*reinterpret_cast<uint8_t**>(
    reinterpret_cast<uintptr_t>(NtCurrentTeb()->ProcessEnvironmentBlock) + 0x368));
  uintptr_t Cursor = Bitmap; uint64_t Writable {}, Virtual {}; unsigned Regions {};
  while (Virtual < UINT64_C(4294967296)) {
    MEMORY_BASIC_INFORMATION Info {}; SIZE_T Returned {};
    const auto Status = NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Cursor),
      MemoryBasicInformation, &Info, sizeof(Info), &Returned);
    if (!Check(!Status && Returned == sizeof(Info) && Info.RegionSize &&
        reinterpret_cast<uintptr_t>(Info.BaseAddress) == Cursor)) return STATUS_UNSUCCESSFUL;
    if (reinterpret_cast<uintptr_t>(Info.AllocationBase) != Bitmap) break;
    if (!Check(Info.RegionSize <= UINT64_C(4294967296) - Virtual &&
        Cursor <= UINTPTR_MAX - Info.RegionSize && ++Regions <= 1024 &&
        Info.State == MEM_COMMIT && (Info.Protect == PAGE_READONLY || Info.Protect == PAGE_READWRITE))) return STATUS_UNSUCCESSFUL;
    if (Info.Protect == PAGE_READWRITE) Writable += Info.RegionSize;
    Virtual += Info.RegionSize; Cursor += Info.RegionSize;
  }
  if (!Check(Virtual && Writable && Writable <= 262144) || !Check(!!M::ObserveMetadata(After))) return STATUS_UNSUCCESSFUL;
  char Text[768];
  snprintf(Text, sizeof(Text), "Pear EC metadata: bitmap_virtual=%llu bitmap_writable=%llu arena=%llu added_leaves=%llu leaf_bytes=%llu fixed_native=%llu view_block=%llu view_slots=%llu\n",
    static_cast<unsigned long long>(Virtual), static_cast<unsigned long long>(Writable),
    static_cast<unsigned long long>(After.mapping_bytes), static_cast<unsigned long long>(After.additional_leaves),
    static_cast<unsigned long long>(After.leaf_backing_bytes), static_cast<unsigned long long>(After.fixed_native_bytes),
    static_cast<unsigned long long>(After.view_block_bytes), static_cast<unsigned long long>(After.available_view_slots));
  const auto Output = reinterpret_cast<int (*)(const char*)>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "__wine_dbg_output"));
  if (!Check(Output != nullptr)) return STATUS_UNSUCCESSFUL;
  Output(Text);
  PearInitCheckpoint("ECMemory.complete", STATUS_SUCCESS, 0, Checks);
  return STATUS_SUCCESS;
}

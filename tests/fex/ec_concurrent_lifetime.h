// SPDX-License-Identifier: MIT
// Original Pear development-only test. Real EC source threads share a live
// owner allocation. Placeholder code is never executed. Process exit reaps the
// parked workers; ordinary ThreadTerm qualification belongs to Stage 5.
namespace PearConcurrentProbe {
namespace M = FEXCore::Utils::PearFEXMemory;
static M::Allocation Shared;
static std::atomic<unsigned> Phase {}, Initialized {}, Active {}, Pinned {}, Done {}, Failed {};
static uint64_t Executors[2] {};
static bool Wait(std::atomic<unsigned>& Value, unsigned Expected) {
  for (unsigned I = 0; I != 10000; ++I) {
    if (Value.load(std::memory_order_acquire) == Expected) return true;
    if (Failed.load(std::memory_order_acquire)) return false;
    LARGE_INTEGER Delay; Delay.QuadPart = -10000;
    if (NtDelayExecution(FALSE, &Delay)) break;
  }
  Failed.store(1, std::memory_order_release); return false;
}
static NTSTATUS WINAPI Worker(void* Argument) {
  const auto Index = reinterpret_cast<uintptr_t>(Argument);
  auto Life = M::AcquireCurrentSourceLifetime(CTX.get());
  if (!Life || !Life.ActualThread() || M::CurrentSourceRole() != PEAR_FEX_ROLE_ARM64EC) {
    Failed.store(1, std::memory_order_release); return STATUS_UNSUCCESSFUL;
  }
  Executors[Index] = M::CurrentExecutor();
  Initialized.fetch_add(1, std::memory_order_release);
  if (!Wait(Phase, 1) || !M::Enter(Shared, 0)) { Failed.store(1); return STATUS_UNSUCCESSFUL; }
  Active.fetch_add(1, std::memory_order_release);
  if (!Wait(Phase, 2)) return STATUS_UNSUCCESSFUL;
  uint64_t Pin {};
  if (!M::Handoff(Shared, 0, Pin) || !Pin) { Failed.store(1); return STATUS_UNSUCCESSFUL; }
  Pinned.fetch_add(1, std::memory_order_release);
  unsigned Polls {};
  while (Phase.load(std::memory_order_acquire) != 3) {
    if (++Polls > 10000 || !M::Poll(Shared, 0, Pin, Shared.Token.write_epoch)) { Failed.store(1); return STATUS_UNSUCCESSFUL; }
    LARGE_INTEGER Delay; Delay.QuadPart = -10000; NtDelayExecution(FALSE, &Delay);
  }
  if (!M::Unpin(Shared, Pin, Shared.Token.write_epoch) || !Life.Validate()) {
    Failed.store(1); return STATUS_UNSUCCESSFUL;
  }
  Life = {};
  Done.fetch_add(1, std::memory_order_release);
  // Never return through the still-unqualified ordinary thread teardown path.
  for (;;) { LARGE_INTEGER Delay; Delay.QuadPart = -10000000; NtDelayExecution(FALSE, &Delay); }
}
}
static NTSTATUS PearRunECConcurrency() {
  using namespace PearConcurrentProbe;
  static std::atomic<bool> Started {};
  if (Started.exchange(true)) return STATUS_SUCCESS;
  PearInitCheckpoint("ECConcurrent.start", 0);
  Shared = M::Reserve(16777216, PEAR_FEX_CLASS_SHARED, PEAR_FEX_ROLE_ARM64EC);
  if (!Shared) return STATUS_NO_MEMORY;
  { M::WriteGuard Write(Shared, 0, 4096); if (!Write) return STATUS_UNSUCCESSFUL;
    memset(Write.Data(), 0, 4096); if (!Write.Publish()) return STATUS_UNSUCCESSFUL; }
  using Create = NTSTATUS (WINAPI*)(HANDLE*, ACCESS_MASK, OBJECT_ATTRIBUTES*, HANDLE,
    NTSTATUS (WINAPI*)(void*), void*, ULONG, SIZE_T, SIZE_T, SIZE_T, void*);
  const auto CreateThread = reinterpret_cast<Create>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"));
  if (!CreateThread) return STATUS_NOT_SUPPORTED;
  HANDLE Threads[2] {};
  for (uintptr_t I = 0; I != 2; ++I) {
    auto Status = CreateThread(&Threads[I], THREAD_ALL_ACCESS, nullptr, NtCurrentProcess(), Worker,
      reinterpret_cast<void*>(I), 0, 0, 65536, 1048576, nullptr);
    if (Status) return Status;
  }
  if (!Wait(Initialized, 2) || !Executors[0] || !Executors[1] || Executors[0] == Executors[1] ||
      Executors[0] == M::CurrentExecutor() || Executors[1] == M::CurrentExecutor()) return STATUS_UNSUCCESSFUL;
  Phase.store(1, std::memory_order_release);
  if (!Wait(Active, 2)) return STATUS_UNSUCCESSFUL;
  const auto Retained = M::Retire(Shared);
  PearInitCheckpoint("ECConcurrent.active-retire", Retained.Status, Retained.ErrorDomain, Retained.ErrorCode);
  if (Retained.Status != PEAR_FEX_QUIESCENCE_TIMEOUT || Retained.ErrorDomain) return STATUS_UNSUCCESSFUL;
  Phase.store(2, std::memory_order_release);
  if (!Wait(Pinned, 2)) return STATUS_UNSUCCESSFUL;
  const auto Saved = M::Retire(Shared);
  PearInitCheckpoint("ECConcurrent.pinned-retire", Saved.Status, Saved.ErrorDomain, Saved.ErrorCode);
  if (Saved.Status != PEAR_FEX_UNAVAILABLE || Saved.ErrorDomain) return STATUS_UNSUCCESSFUL;
  Phase.store(3, std::memory_order_release);
  if (!Wait(Done, 2)) return STATUS_UNSUCCESSFUL;
  auto Stale = Shared;
  if (!M::Retire(Shared) || M::Enter(Stale, 0).Status != PEAR_FEX_STALE_IDENTITY) return STATUS_UNSUCCESSFUL;
  for (auto Handle : Threads) if (NtClose(Handle)) return STATUS_UNSUCCESSFUL;
  PearInitCheckpoint("ECConcurrent.complete", 0, 0, 2);
  return STATUS_SUCCESS;
}

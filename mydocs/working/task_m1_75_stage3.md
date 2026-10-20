# Task #75 Stage 3 — WGI source and selected PE correspondence

GitHub Issue: [Pear #75](https://github.com/postmelee/pear/issues/75)
Implementation plan: Pear `mydocs/plans/task_m1_75_impl.md`, approved continuous Stage 3 scope after `c0eb4a8`.
Stage: 3

## Stage Purpose

Establish whether the selected development WGI module corresponds to the retained
Wine source and build inputs, using an isolated module reconstruction. Context:
Pear root/test rules, the approved Task #75 plan, the artifact retention guide,
the stage-report skill and central template, existing Wine/common-runtime build
code, and the exact retained Task #5 producer records. Natural-call observation
and behavior repair remain later work.

## Artifacts

| File | Change summary |
|---|---|
| `pear_runtime/recipes/wgi.py` | Sealed explicit-input WGI adapter, dependency/trace admission, raw comparison and bounded finalization |
| `recipes/wine/wgi-v1.json` | 9,152 declared inputs and 65 recorded generation/compile/link actions |
| `tests/build/test_wgi.py` | 26 synthetic acceptance/refusal methods using the existing synthetic PE helper |
| `recipes/wine/README.md` | Separate WGI invocation, input, comparison, diagnostic and storage boundaries |
| This report | Verified results, timings, retention and next-work limits |

## Body Change Scope / Lossless Preservation

Runtime branch base: `17516d76d02d5ddd15d477bf5604cf7fda6be5b1`.
The existing common executor, Wine recipe driver and imported source are unchanged.
The new adapter reuses their stable input reader, dependency parser, process/lock
supervision, snapshots, ARM64X parser, COFF/PE timestamp derivation and strict
link-trace admission. It does not invoke the historical full Wine builder.

The selected source subset is 173 files at Wine
`007291b81de386fd8886770c33b5d385c078635d`. Exact subset comparison also matches the
retained source and the corresponding files at upstream
`4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf` and Task56 selected bounded Wine build
pin `1b76db6902345388c589ba3909b22badf751dfd5` (which did not build WGI). This is
not a whole-tree equivalence claim.
Neither Wine code nor existing candidate bytes changed.

The original 65 argv arrays retain source spelling `../source/`, architecture
settings and absence of optimization flags. Reviewed adaptations are explicit
LLVM roots, the arm64 host wrapper, a pinned compiler PATH for Wine's space
splitting, compiler dependency and verbose link diagnostics, and one extra
control link. The exact relative `./tools/winebuild/winebuild` diagnostic field is
resolved against its recorded command directory and admitted output identity in
separately hashed derived logs. Original logs and executed argv remain intact;
other relative child paths refuse.

New original Python files retain Pear's 2026 GPL-3.0-or-later headers. Existing
Wine, LLVM and imported generator/library terms remain unchanged. The JSON
recipe contains source-relative identities; private bindings, old paths and
binary payloads are not committed.

## Verification Results

This is a build/source/portable-test result on macOS using Python 3.13.5,
Clang 23.1.1 and the exact admitted host tools. Host build tools ran through the
arm64 wrapper; targets are `aarch64-windows` and `arm64ec-windows`, linked as
ARM64X. No runtime, guest fixture, PE or game executed. No SDK dependency appeared
in the actual compiler depfiles. There is no installation, signing or activation.

The public recipe SHA-256 is
`16b35a33816e5846f3dbd46620e066a0b9a557d3f77aacb839042a975dd9141f`.
Its independently reviewed original action/input plan is pinned as
`64a3fe23165dfae82badcec179771aec743f16bf20806170bd8d8d8c85563fd1`.
The successful captured WGI driver SHA-256 is
`6b621c2a16fa113a56d751910710886f194b5507a27723f91fcdfbc602a2df7e`.
The final build receipt is
`8a8f24211bb990e81d881409de870b5ca59d17c0bdc94e61fc1a6b6874c82ff2`
(3,857,433 bytes); its exact private path is retained by the Task #75 evidence
handoff. Independent actual-artifact review rehashed 1,308 distinct
identities and confirmed the same gates; its receipt SHA-256 is
`e6bf558029cea130430867187a9685ab169d35dd9a70375fa935f17ff53766b1`. Documentation changes after this source freeze do not change that
producer identity.

Executed validation uses the following entrypoints; variables identify explicit
private roots and do not authorize execution from a saved pass:

```sh
cd "$RUNTIME"
python3 -B "$EVIDENCE/run_portable.py" --runtime "$RUNTIME" --receipt "$EVIDENCE/portable-05.json"
python3 -B -m pear_runtime.recipes.wgi --recipe "$RUNTIME/recipes/wine/wgi-v1.json" --bindings "$PRIVATE_WGI_EVIDENCE/bindings-v1.json" --output "$OWNED_WGI_ATTEMPTS/wgi-v2"
python3 -B "$PEAR/tools/check_source_notices.py" --base 17516d76d02d5ddd15d477bf5604cf7fda6be5b1
git diff --check
```

- 43 synthetic methods passed: 26 WGI controls and 17 existing Wine controls,
  under process/native/network guards. An independent package-qualified run
  also passed. Coverage includes changed or self-declared recipe identity,
  missing/mismatched/mode-changed inputs, source aliases, absent or shadow
  depfile source, unknown dependencies, command-directory operand binding,
  unknown/missing child tools, changed logs, code/RSDS/ARM64X changes, retained
  prior-attempt storage, final-receipt overflow and finalization interruption.
- All 9,152 inputs passed admission. All 66 actual commands exited zero:
  36 generator actions, 28 compiler actions and two links. All 36 generated
  outputs matched their retained reference bytes.
- All 28 raw compiler objects were preserved. Each matches its reference outside
  the four-byte COFF timestamp. Only separate working link operands received
  the explicitly derived reference timestamp; raw objects were not overwritten.
- All 28 actual depfiles were admitted: 133 unique paths, comprising 101 declared
  Wine source files and 32 generated inputs. Generator input closure remains the
  declared Makefile/source graph and exact output comparison, not a syscall
  read trace. Each link admitted all 39 required object/archive operands,
  41 actual file reads and all three child tool identities. No unknown dependency
  was ignored or admitted by path prefix alone.
- The original candidate, runtime12, retained installation and retained build
  DLLs were freshly rechecked at SHA-256
  `ee23564869279df291d84b80029f196137117870eb65830fe47e8334073332d2`,
  1,114,112 bytes. The final raw rebuilt DLL has SHA-256
  `2399c75b0cdc5a4c95249502abea9e9afe5b1003296d1a22172169d79dfcfb0e`.
  Raw equality is false. In-memory derivation changes only the four-byte COFF
  timestamp at offset 128 and debug timestamp at offset 531392; the resulting
  whole file equals the original exactly. RSDS, code, imports, unwind data,
  CHPE metadata and ARM64X machine fixup are unchanged. The control link also
  passed this same complete comparison.
- The outer operation observed CLI exit zero, passed build status,
  `wgi_finalization_complete=true`, and released lease. Builder sources and all
  281 original pack-source files remained unchanged. A saved receipt alone is
  not execution authority. The unchanged core's legacy Task56 operation-envelope
  label is explicitly identified; this build is Task75 reconstruction only and
  `runtime_eligible=false`.
- First attempt: the control link exited zero, but the absolute-only trace parser
  refused the relative Wine helper field. Its raw DLL, logs, snapshots and failed
  receipt remain intact. A separate pure replay proved the narrow diagnostic
  adaptation; it did not relabel that attempt as passed. The earlier read-only
  preflight harness's absent-future-output path error also remains historical.
- Incremental source notices and whitespace/privacy review passed. The JSON
  recipe and Markdown are separately reviewed formats, not source-notice
  automation coverage or legal clearance.

Evidence reuse is confined to exact retained lower-layer objects, libraries,
generator tools, LLVM inventory and unchanged source/Git correspondence. The
fresh reconstruction does not reuse a historical execution pass. No native or
game qualification was repeated or inferred.

Measured successful outer build interval: 15.576 seconds, from
2026-10-20 15:08:04.121753 UTC to 15:08:19.698199 UTC. Child process interval:
15.462 seconds. Preparation/admission and individual actions have both wall and
monotonic boundaries in the receipts. Aggregate phase durations are preparation
0.156 s, input admission 2.413 s, generation 0.993 s, compilation 2.912 s, linking
1.072 s, comparison 0.726 s, final input validation 2.026 s and lock acquisition
0.000074 s; these are not summed into an end-to-end latency claim. Pack preparation
was 0.253 s and the retained first failed attempt was 5.395 s. Human review waiting
is separate and not included in the successful build interval. A user-operable
window/manual-input endpoint is **Not applicable** to this build-only task.

## Artifact Disposition

| Artifact/root | State and outcome | Remaining owner/consumer | Identity/recovery | Retain/release condition |
|---|---|---|---|---|
| Versioned WGI source/recipe/tests/report | New reviewed source; no publication claim in this report | Task #75 and next WGI investigation | This stage's source commit and captured hashes above | Retain authoritative history |
| New immutable 281-file input pack | Retained exact copies; originals preserved | Reproduction/review | Private staging manifest and pinned public recipe | Keep until replay/recovery consumers explicitly release it |
| Original source, helpers, compiled libraries and LLVM installation | Read-only retained dependencies | Existing tasks and WGI replay | Exact original/current input manifests | No release authorized; Git alone cannot restore compiled operands |
| Failed attempt and pure diagnostic replay | Retained unique failure evidence | Trace/admission review | Separate failed receipt, raw files and derived replay | Keep through accepted investigation handoff; no deletion performed |
| Successful attempt, raw objects/PEs and all receipts | Retained reconstruction evidence | Independent review and natural-call planning | Successful build digest above | Preserve raw/derived distinctions until consumers accept release |
| Existing candidates, prefixes, game/installation/private state | Untouched | Existing owners | Existing identities; four WGI modules rechecked | No release, mutation or execution authorized |

The pack is 57,220,780 logical / 57,802,752 stat-allocated bytes. The retained failed
attempt is 23,231,450 / 23,797,760 bytes; the successful attempt is 27,600,038 /
28,651,520 bytes. At external post-release measurement the whole new campaign,
including both attempts, pack and then-current private evidence, was 108,280,808
logical / 110,501,888 stat-allocated bytes, below 134,217,728 bytes (128 MiB).
Later bounded text handoff additions are separately accounted. The initial source
worktree/audit allowance is separate. No runtime/toolchain/prefix copy or cleanup
occurred. The existing LLVM inventory covers 782,265,656 logical bytes and was
reused read-only.

Filesystem free space was 17,810,632,704 bytes before and 17,779,208,192 after the
successful outer interval; the 6 GiB reserve remained available. Concurrent work,
APFS sharing and allocation prevent attributing that net change exclusively to
this build. Stat-allocated size is not a promise of reclaimable bytes.

## Residual Risks

- This establishes selected-module source/PE correspondence using explicit retained
  inputs. It is not a complete clean Wine/toolchain bootstrap or proof that a
  future game process naturally loads or calls this module.
- The suspected WGI provider failure branch, HRESULT/output propagation and game
  initialization path remain observation hypotheses, not an established cause
  of the loading failure. No behavior was repaired or tested in a game.
- Private input manifests and preserved compiled operands remain prerequisites;
  source publication does not make this route clean-clone reproducible. The
  separate Stage2 publication review and visibility decision remain unchanged.
- Current source and exact captured producer bytes are distinguished from historical
  build pins, selected runtime tool roots and later documentation commits.

## Impact on Next Stage

The natural-call investigation can now bind the provider/controller/gamepad source
to this exact selected PE. It must observe actual module identity, calls, branch,
HRESULT and completed writes without extra polling or reading unwritten outputs.
Current execution authority, ownership, resource bounds and cleanup must be
established for any later approved runtime operation. No observation or repair is
authorized by this report alone.

## Approval Record

The requester approved continuous completion of all three Task #75 stages with
verification/report/commit gates. The parent reviews this component source/report
bundle before its commit. Public visibility, game execution and deletion remain
outside the approved scope.

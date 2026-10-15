# Task #56 Stage 5.2: exercise the isolated development selection

Issue: [#56](https://github.com/postmelee/pear/issues/56).
Context: the approved Task56 plans, Stage 5.1 report, applicable source/document
rules, stage-report skill and artifact-retention procedure.
Evidence identities and current changed-file inventory are in the adjacent
`task_m1_56_stage5.2.json`. This completes Stage 5; final source-owner cutover
and private publication identity checks remain Stage 6 gates.

## Stage Purpose

Bind the committed development tools, exercise the actual Pear selector and
required seven synthetic controls, inspect the exact game inputs and demonstrate
metadata recovery without copying or executing the game.

## Artifacts

- Exact development lock at Pear `tools/development/locks/task56-development-v1.json`.
  The exercised private immutable copy has the same 1,508 bytes and SHA-256
  `932ea9eb3e9218e13bf514b6dc6b1736f7e714d10ce3008af0b538a9d74dc08f`.
- Updated existing READMEs/developer guides and implementation plan reflect the
  executed paths, required retained inputs, support limits and recovery semantics.
- Source-bound fixture/game descriptors, seven execution records, three fresh
  independent-release records and the prepared/selected/inspected game state.
- This report and sanitized evidence identities. Detailed paths and raw private
  observations remain outside Git; no game/profile/account bytes are imported.

## Body Change Scope / Lossless Preservation

No runtime execution, result-oracle or Pear game/selector code changed after runtime tool
`6f0202b457f0e585c5c7621a63d203e77d07386d` and Pear execution source
`0453474ba59b5a853d58d9556d849c175ad4677a`. FEX parser/tool stays at
`9c9b602c07b57a08500862abfdf62e1bac351640`. Component compilation pins,
build receipts, reconstruction lock, signatures and candidate3 are unchanged.
Source-report/document commits are distinct from the executed tool commits.

Two preparation failures are retained. First, a state directory inside the
metadata input parent failed `state_input_overlap`; it was never created.
The selected state is instead a sibling of the task metadata parent. Second,
the initial v4 fixture failed `assembly_builder_changed` before the owned
runtime launch: candidate3 binds ten absolute builder facts, including their
canonical source paths, rather than hashes alone. The recorded operation's
`runtime_execution_performed: unknown` remains unchanged. Prefix/source
preparation had occurred, and its outputs are retained.

The correction changes worktree roles, not the admission policy. The original
`runtime-task56` root is a clean detached immutable 6f selected tool root;
`runtime-development-v1` holds the editable `codex/task56` branch for later
reports and work. All ten builder files match candidate3's recorded full facts.
The source-only checkout cost and failed v4 evidence remain recorded. A future
different tool root needs a reviewed new assembly/record and fresh bindings;
equal commits alone do not authorize moving this retained candidate's sources.
Historical Stage 5.1 planning/report text is preserved and superseded here.

The actual Wine source-check command exposed an older metadata admission gap:
its upstream-diff gate rejected committed Stage4 reports and the source-notice
exception list. DXMT uses the same gate and would reject the new report after
staging. Preserve the observed refusal. A narrow component verification-tool
correction admits only the explicitly named approved metadata paths; it does not
allow arbitrary `mydocs/` or `.github/` changes. Selected source hashes/modes,
ancestry, private-header exclusion and peer-header checks are unchanged. Focused
positive and unrelated-source/near-miss refusal checks plus the actual documented
commands verify the correction. Each component source-audit suite passed 20
tests (nine existing and eleven new); FEX's actual check independently passed 99
selected sources and both shared-header joins without a tool change. These are
source-audit tool/test changes, not
new component compilation or candidate/producer identities.

## Verification Results

The actual Pear selector prepared, selected and inspected the fixture candidate.
The seven v5 operations then passed TLS/thread, SEH/unwind, suspend/context,
code invalidation, guest-fault/guard, configured-memory and original rendering
checks on candidate3. Each retained the canonical owner, current before/after
authority, original assertions, descendant cleanup and release requirements.
The independent review joined all seven operation/result sets, 42 original
result predicates and 511 captured producer records. Two review-harness mistakes
were retained and corrected without changing any production oracle or result.

Three newly executed independent resource checks passed for all 15 operations:
the seven fresh fixtures plus eight retained native/bootstrap/frame controls.
Each uses the original process/handle/lock queries and two observations. The
eight earlier native/control execution claims remain historical, not new runs.
The failed v4 preloader operation received its own bounded two-observation
resource check; it is not relabeled as a completed fixture release.

The current prerequisite packet joins these exact operations and release records.
Game metadata preparation and real selector inspection admitted all 69 original
game inputs and 92 source producers (73 runtime, 14 Pear, 5 FEX), with current
source bytes equal to the explicit Git blobs. The game output directory stayed
empty. Game selection → retained fixture selection → the same game selection
passed, including final reinspection and immutable transaction joins. This
proves selection-metadata recovery only; game copy/execution remains unperformed.

Executed command forms (the private invocation receipts identify every concrete
path, interpreter, argv, cwd and output; use fresh outputs for a future run):

```sh
"$PYTHON" -B -m tools.development.runtime_candidate prepare --spec "$SPEC"
"$PYTHON" -B -m tools.development.runtime_candidate select --prepared "$PREPARED"
"$PYTHON" -B -m tools.development.runtime_candidate inspect --state "$STATE" --kind fixture
"$PYTHON" -B -m tools.development.runtime_candidate diagnose-fixture --state "$STATE" --request "$REQUEST"
"$PYTHON" -B -m pear_runtime.fixtures.release_controls --request "$RELEASE_REQUEST" --output "$FRESH_RELEASE"
"$PYTHON" -B -m pear_runtime.fixtures.release --request "$RELEASE_REQUEST" --output "$FRESH_RELEASE"
"$PYTHON" -B -m tools.development.runtime_candidate inspect --state "$STATE" --kind game
```

The runtime source root is the cwd for the release modules; Pear is the cwd for
its selector. The actual interpreter alias resolves to the retained ARM64
Python 3.14.4 binary. The selected native host remains macOS 26.5.2/Xcode 26.6.
Existing Apple-tooling guidance and artifact-specific authorization apply; no
security setting changed. No operation above qualifies gameplay or distribution.

Stage 5.1 source/portable results remain valid on unchanged execution sources:
777 runtime IDs/763 bodies, 130 Pear-game IDs/115 bodies, 38 selector repository
tests plus four independent probes, and 154 contracts plus schemas/examples.
They overlap and must not be summed. Current recovery collection includes 21
methods; twelve recovery inputs remain unchanged from Stage 4. Historical actual
restoration covers one 3,634-byte shared-header input and binding metadata on
candidate2, not a full candidate3/toolchain/private-state restore. The manager
whole-file manifest mismatch/unavailable later binary limitation remains exactly
as recorded in Stage 5.1; no current manager build/pass is claimed.

Final protection rehash: 307 frozen runtime source/mode entries and 29 selected
original identities unchanged. This is bounded protection evidence, not an audit
of every original file or other workers' concurrent Git changes. The final
documentation review covered 15 approved files, 73 added links, 40 shell blocks
and 12 interfaces; `git diff --check` passed. This is static command/interface
review, distinct from the actual source-check commands above. Exact
review evidence is included in the adjacent JSON. Original upstream README and
Pear manager blocks remain preserved.

## Artifact Disposition

| Artifact | State and remaining consumer | Retention / recovery condition |
| --- | --- | --- |
| Selected immutable runtime/FEX tools and build source pins | Retained development inputs | Keep exact commits, clean selected roots and path bindings until successor admission |
| Editable runtime source/report worktree | Current Task56/future runtime source authority after acceptance | Separate from the selected tool root; do not silently repin executed tools |
| Candidate3, immutable packs and declared old tools/objects | Retained reconstruction and diagnostic dependencies | No deletion authorized; bounded reconstruction is not a full clean rebuild |
| v4 failed prefix/operation and v5 successful outputs | Unique failure and current required evidence | Retain until downstream replay/evidence dependencies are explicitly released |
| Game descriptor/selection and69 original inputs | Metadata plus existing private input owner | No game copy, execution, state migration or deletion |
| Exact frame-request path | Required live historical-input binding | 494-byte backup and path/hash/size restore mapping verified; missing original path must be restored exactly, never silently rebound |
| Private raw evidence and curated digest index | Stage/final handoff evidence | Preserve referenced exact bytes; final durable archive tracked in Stage 6 |
| Original Preview/runtime/prefixes/saves/signing material | Existing owners | Preserved and outside Task56 activation/cleanup scope |

The source-only checkout measured 18,364,183 logical and 19,116,032 allocated bytes
under a 128 MiB allowance plus 6 GiB reserve. The serial seven-control budget was
13,422,347,155 additional bytes plus6,442,450,944 reserve; execution observed
21,645,533,184 free bytes before and 21,495,009,280 after. This is a filesystem
net change with concurrent-work/APFS uncertainty, not allocation attribution.
The final protection observation saw 21,445,873,664 free bytes. No additional
deletion occurred in Stage 5.2. Latest reviewed large remnants remain KEEP because
last replay/recovery consumers have not released them; previous deletion
approvals are not extended.

## Residual Risks

Game execution, the existing Loading/ECGate failure, Steam/player support, full
Rosetta-independence coverage and cold-prefix initialization remain unresolved
or unperformed. Source-root and one small exact temporary-path binding remain
explicit retained dependencies. Private input/header/toolchain availability is
required for bounded reconstruction. The exact selected candidate is usable for
development but is not generally distributable or a clean-machine qualification.

## Impact on Next Stage

Obtain final source-owner acceptance after comparing later owner changes. Publish
the approved private component branches, verify their exact refs/visibility,
persist curated private evidence and record final source/test ownership, next
Megabonk work, retention and recovery. Public Pear publication remains unapproved.

## Approval Record

Continuous in-scope progression, verification, reports and bundled commits are
already approved. No repeated stage confirmation is required. Additional
deletion, public publication, scope expansion and existing environment/Preview
changes remain excluded.

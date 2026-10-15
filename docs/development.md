# Reconstructing a development runtime

This guide belongs to [Pear Task #56](https://github.com/postmelee/pear/issues/56).
The selected source lives in the private [Wine](https://github.com/postmelee/pear-wine),
[FEX](https://github.com/postmelee/pear-fex) and
[DXMT](https://github.com/postmelee/pear-dxmt) repositories; collaborator access is
required. The common runtime owns input admission, component recipes, assembly
and cross-component diagnostics. Pear retains application and game/account policy.

## Current reconstruction boundary

The first reconstruction is a bounded development build, using fixed component
commits and explicitly preserved lower-layer objects, archives, generated
configuration and toolchains. It is not a clean rebuild of every upstream target.
Changing a preserved object's source, compiler or configuration requires rebuilding
that object and updating its manifest; an old digest cannot validate new inputs.
A missing preserved operand is a restore-required input, not permission to search
an old worktree or substitute another version.

The historical D25 generator was recovered as a distinct original source artifact.
Its original execution did not pass overall. Current recipes are reviewed successor
procedures; they do not silently execute the newer historical helper. Compiler
arguments and retained object identities are traceable to the selected build
records. Historical environment values absent from those records are unknown;
new recipes record their complete declared environment and adaptations.

## Current verification status

Stage 3 reconstructed the selected component artifacts. Candidate3 is a later
signed development assembly using the same component build records and artifact
refs. The recorded comparison checks all 2,824 bundle entries and 41 Mach-O
code origins; their permitted differences are signing metadata. This does not
renew historical fixture operations or grant current execution authority.

All fifteen fresh candidate3 controls passed with independent release evidence:
API, ABI, threads, window, three bootstrap controls, the seven D36 cases and
visible presentation frames. The frame check covers three cycles and eighteen
visible pixel/color/resize matches and GPU completion/present observations; three
presented timestamps were positive and fifteen remained zero. The accepted reuse plan retains candidate2 CPU-specific, ordering,
device, pairing and original-presentation evidence only within their unchanged
input/source/payload scope. The AVX case remains explicitly unsupported with
exit 77. Candidate2's unlocked eighteen-frame observation passed; earlier capture
and native-window failures remain retained, not relabeled as passes.

The Stage 4 portable evidence records 715 unique test IDs / 701 method bodies passed
and a separate 174-test build/assembly gate. These overlapping evidence scopes are
not summed and are not native or game qualification. The
[196-method ownership map](../provenance/paired-memory-methods.json) has accepted
per-method dispositions. The recorded Stage 4 component checkpoints are published
on the private repositories; collaborator access is required. Stage 5 publication
and final source-owner cutover remain separate gates. Pear
development selection uses separate Stage 5 source and execution gates. There is no gameplay, Steamworks, ordinary-user distribution, full clean
restore or complete Rosetta-independence claim.

## Selected source and commands

The [selected lock](../locks/task56-reconstruction-v1.json) records actual fork
commits, recipe digests, source/submodule pins and pre-signing artifact identities.
Use the enclosing runtime revision recorded by Pear's Stage 3 report; retain that
commit even when later documentation changes the branch tip. Check out component
pins without local tracked changes, and materialize the pinned FEX submodules.

Run the [FEX](../recipes/fex/README.md), [Wine](../recipes/wine/README.md), then
[graphics](../recipes/graphics/README.md) commands sequentially with fresh outputs.
Their local bindings name the exact external toolchain, SDK and immutable packs;
there is no old-worktree discovery. Inspect and then execute the reviewed assembly
request described in [assembly.md](assembly.md). Preserve both CLI-returned
`runtime_ref` and `operation_ref` for subsequent current-authority admission.

The first selected FEX build differs from its predecessor only in 14 timestamp
and debug-identifier bytes. Wine native and all three graphics outputs are
whole-file equal; Wine PE is whole-file equal after explicit recorded timestamp
normalization. This comparison does not replace affected host controls.

The builder's final absolute-executable guard was added after the selected FEX
and Wine builds. Their retained producer snapshots differ only by that guard and
its comments; every recorded executable is absolute. Independent review permits
reuse of those exact builds. Graphics and assembly use the guarded builder. A new
build uses the current source and records its own producer snapshot.

## Build pins and later development revisions

The following completed build identities remain fixed. A later test commit is
not evidence that the earlier artifact was built from that commit. The private
component repositories use the development branch `codex/task56`; the exact
Stage 4 revisions below were verified on their private remotes.
The three upstream forks retain their original pin as `upstream/pinned`; this is
an upstream reference, not a new integration branch. No `master` integration
branch or completed merge is claimed. Use explicit refs and commits below,
independently of the repository's default branch.

| Repository | Upstream base | Selected build/source commit | Later development checkpoint |
| --- | --- | --- | --- |
| Wine | `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf` | `1b76db6902345388c589ba3909b22badf751dfd5` | Stage 4 tests/API fixture `d31a50d7385b3385ab278e0fe7687b9d1267de94` (published privately) |
| FEX | `59f85d6b7df4eb053d2cc1b9d33411b4f31bfbaa` | `c62ed75aa6a33809ddb76c7f40aabbe4f4fbdda6` | CPU export `9c9b602c07b57a08500862abfdf62e1bac351640`; Stage 4 exports/metadata `a8ba1cbd0148b46817842f3b7307689d4b2acbd7` (published privately) |
| DXMT | `7c8dee1c2d73415301ceb7d1fa810861cef4cd67` | `e800e770006fc7c37831ab857000a4781c85f6fd` | Same committed checkpoint at this review |
| Common runtime | Pear contract source `bcd27806da5c9885cfcf40e639ae02b2c400e3c1` | Builder `c8887f9edaba57dffe7772cc26fd19aa9571d451` | Seven fixtures `c13c7030ec3b780df12373cb9e0460bbcb5b0652`; Stage 4 tools `625fd0f97b9955e43f71cb7906ccc41d8f70853b` (published privately) |

The selected Wine native ARM source and Wine 11/CodeWeavers Preview are separate
lineages. The merged fork source view also differs from the per-artifact source
views of explicitly retained lower-layer objects. Preserve both distinctions.
Use a separate development checkout for current admission and fixture tools;
keep historical build roots clean and pinned. The [Stage 4 report](../mydocs/working/task_m1_56_stage4.md)
binds the completed candidate3 controls to these published private tool/test
checkpoints. Stage 5
lifecycle/selector changes require a later reviewed source checkpoint and affected
verification; a dirty checkout does not inherit the Stage 4 producer identity.

Collaborator links to the local committed checkpoints are
[runtime](https://github.com/postmelee/pear-runtime/tree/625fd0f97b9955e43f71cb7906ccc41d8f70853b),
[Wine](https://github.com/postmelee/pear-wine/tree/d31a50d7385b3385ab278e0fe7687b9d1267de94) and
[FEX](https://github.com/postmelee/pear-fex/tree/a8ba1cbd0148b46817842f3b7307689d4b2acbd7).
They require private-repository access. Their exact Stage 4 commits were
verified on the private remotes. Stage 5 source has a separate publication gate;
historical source acquisition below does not fetch unpublished commits.

### Keep the selected tool checkout immutable

After the Stage 5.1 source/portable checkpoint, create a separate source-only
detached checkout at that exact runtime tool commit. The planned task location
is `.worktrees/runtime-development-v1` under the component workspace. Bind this
clean checkout in the development lock, fixture/game producer manifests and
Pear selection; keep later documentation and reports on `runtime-task56`. The
selector checks clean Git state and committed producer bytes, so later edits
must not silently change the selected tool root.

The source-worktree plan allows 128 MiB additional space and retains a separate
6 GiB host reserve. It copies no runtime bundle, input pack, prefix or game.
Measure free space again before creation. Retain this exact source checkout
until every selected producer and diagnostic consumer accepts a successor;
this plan grants no deletion or execution authority.

### Acquire clean historical roots

The following source-acquisition commands are documented procedures; they were
not part of the small recovery exercise. They require separate capacity planning.
Set `RUNTIME_REPO`, `WINE_REPO`, `FEX_REPO`, `DXMT_REPO` to existing full-history
repositories and `HISTORICAL_ROOT` to a canonical task-owned parent. Every child
below must be absent. Preserve the current development checkouts. If the named
commits are not present locally, fetch the explicit published development ref;
a default-branch checkout is not part of this procedure:

```sh
for COMPONENT_REPO in "$RUNTIME_REPO" "$WINE_REPO" "$FEX_REPO" "$DXMT_REPO"; do
  git -C "$COMPONENT_REPO" fetch origin refs/heads/codex/task56
done

git -C "$RUNTIME_REPO" worktree add --detach "$HISTORICAL_ROOT/runtime" c8887f9edaba57dffe7772cc26fd19aa9571d451
git -C "$WINE_REPO" worktree add --detach "$HISTORICAL_ROOT/wine" 1b76db6902345388c589ba3909b22badf751dfd5
git -C "$FEX_REPO" worktree add --detach "$HISTORICAL_ROOT/fex" c62ed75aa6a33809ddb76c7f40aabbe4f4fbdda6
git -C "$DXMT_REPO" worktree add --detach "$HISTORICAL_ROOT/dxmt" e800e770006fc7c37831ab857000a4781c85f6fd

git -C "$HISTORICAL_ROOT/fex" submodule update --init --recursive --checkout -- \
  Source/Common/cpp-optparse External/fmt External/range-v3 External/rpmalloc \
  External/unordered_dense External/xxhash
git -C "$HISTORICAL_ROOT/dxmt" submodule update --init --checkout -- include/native/directx
```

Verify each submodule against the selected lock. The DirectX gitlink is
`9df86f2341616ef1888ae59919feaa6d4fad693d`. New local binding files name these exact
clean Git roots and their submodules. Wine's `common_headers` and FEX's runtime
header input are content-pinned; bind the admitted original header bytes, not an
independently edited copy. All other pack/toolchain/SDK/private roots still need
their exact declared bytes. Public source history does not recover those inputs.

### Reconstruct the selected artifacts

These are the exercised recipe interfaces with machine-local paths replaced by
named variables. Set every variable explicitly from the reviewed input inventory;
no variable is an implicit search path. Run from the historical runtime checkout,
sequentially, after admission and capacity review, using fresh output directories:

```sh
python3 -B -m pear_runtime.recipes.fex --recipe recipes/fex/selected-v1.json \
  --bindings "$FEX_BINDINGS" --private-manifest "$FEX_PRIVATE_MANIFEST" \
  --output "$FRESH_FEX_OUTPUT"
python3 -B -m pear_runtime.recipes.wine --recipe recipes/wine/selected-v1.json \
  --bindings "$WINE_BINDINGS" --output "$FRESH_WINE_OUTPUT"
python3 -B -m pear_runtime.recipes.graphics --recipe recipes/graphics/selected-v1.json \
  --bindings "$GRAPHICS_BINDINGS" --output "$FRESH_GRAPHICS_OUTPUT"
```

The selected reconstruction compiled three FEX, three Wine and five graphics
units and reused declared immutable lower layers. Keep every recipe's explicit
storage allowance plus the separate 6 GiB host reserve. Complete toolchains,
SDKs, generated configuration and object/archive packs remain prerequisites;
this command list does not bootstrap them.

For a new implementation experiment, commit the component change, create a new
reviewed recipe/input-pack version and map every changed compilation unit and
link operand. Review intended artifact differences and affected behavior. Do not edit the old lock or treat a new digest as semantic acceptance. Current
admission checks identity and required-header use; changed implementation behavior
still needs affected source-owner and fixture review. The selected FEX comparison
reports baseline code differences, while its strip check protects fresh debug-to-
stripped executable text; neither is a generic source-symbol ownership oracle.

## Input and output contract

`pear_runtime.build.Context` admits a recipe with schema version 1, a name,
explicit named roots, exact file identities and a storage budget. Roots are Git
checkouts, immutable inputs, toolchains, SDKs, private inputs or host tools.
A separate local JSON binding maps those names to canonical absolute directories.
Keep this binding, build receipts and private configuration outside Git.

A Git root must have the pinned commit checked out and no tracked changes. A
consumed source must match its committed blob. Submodules have separate pins and
bindings; a parent gitlink does not admit arbitrary files beneath it. Other input
files require SHA-256 and size, with mode where relevant. Symlinks require their
exact target and an admitted target file. Include directories alone do not admit
every file within them: actual dependency files are checked after compilation.

An output must be fresh, have a canonical existing parent and be separate from
all input roots. The build holds an exclusive live operation lock. It verifies
actual free space against the component's additional allocation and the retained
host floor before creating outputs. A recorded previous lock release is not a
current lease. Sequential component builds avoid unplanned peak overlap.

Commands execute only within their owned output tree, with explicit arguments,
working directory and environment. No caller shell environment, cache wrapper or
private credentials are inherited. Each command retains bounded stdout/stderr,
exit code and timing. Time or output limits terminate only the command's owned
process group, including surviving descendants after the leader exits. Failed
operations retain their original error and failure receipt.

Generated operands must be recorded before consumption and must retain their
recorded bytes. A successful component receipt rechecks admitted inputs and
outputs, records dependency evidence and identifies its artifacts. It explicitly
leaves `runtime_eligible` and `game_qualified` false. Assembly, current signing
and execution authority, affected fixture verification and game qualification
are distinct steps.

The [assembly interface](assembly.md) describes the exact private request, read-only
planning, static signing review and explicit creation of a fresh development
candidate. It preserves current authority checks and does not launch the runtime.

## Portable build-tool checks

From this repository root:

```sh
python3 -B -m unittest discover -s tests/build -p test_build.py -v
```

These checks use isolated temporary files and synthetic processes. They cover
input changes and missing bindings, output aliases, operation contention, capacity
refusal, command failure, bounded logs and process cleanup, declared dependency
paths, Git source identity and retained receipts. They do not invoke Wine/FEX,
use signing material, run a game or establish host runtime support.

## Assembly and fixture interfaces

The following command forms were exercised with reviewed local requests. Paths
are supplied by the caller; request contents and private identities stay outside
Git. Each request binds its own exact candidate, final assembly operation,
producer/context inputs, profile, fixture and output. A label or a saved success
record grants no current execution authority.

```sh
python3 -B -m pear_runtime.assembly inspect --request "$ASSEMBLY_REQUEST"
python3 -B -m pear_runtime.assembly execute --request "$ASSEMBLY_REQUEST"
```

Use the historical builder revision for the recorded component reconstruction.
Candidate3 assembly and current fixture/recovery commands use the separately
captured Stage 4 developer-tool source. Preserve every historical producer record
and bind the actual source revision used for each new operation.
Read [the assembly contract](assembly.md) before constructing the request. Preserve
both returned `runtime_ref` and final `operation_ref`.

From the reviewed developer-tool checkout, inspect a request before its explicit
owned execution. `ARM64_PYTHON` is the admitted absolute interpreter path. The
runtime's current-authority and exclusive-operation gates still apply:

```sh
python3 -B -m pear_runtime.fixtures inspect --request "$FIXTURE_REQUEST"
/usr/bin/arch -arm64 "$ARM64_PYTHON" -B -m pear_runtime.fixtures execute --request "$FIXTURE_REQUEST"
python3 -B -m pear_runtime.fixtures.release \
  --request "$RELEASE_REQUEST" --output "$FRESH_RELEASE_RECORD"

python3 -B -m pear_runtime.fixtures.controls.execution inspect --request "$CONTROLS_REQUEST"
/usr/bin/arch -arm64 "$ARM64_PYTHON" -B -m pear_runtime.fixtures.controls.execution execute --request "$CONTROLS_REQUEST"

python3 -B -m pear_runtime.fixtures.native inspect --request "$NATIVE_REQUEST"
/usr/bin/arch -arm64 "$ARM64_PYTHON" -B -m pear_runtime.fixtures.native execute --request "$NATIVE_REQUEST"

python3 -B -m pear_runtime.fixtures.controls.cpu_driver inspect --request "$CPU_REQUEST"
/usr/bin/arch -arm64 "$ARM64_PYTHON" -B -m pear_runtime.fixtures.controls.cpu_driver execute --request "$CPU_REQUEST"
```

These are distinct contexts, not interchangeable request templates. The graphics
controls require a current verified device operation before native pairing;
pairing retains its exit-0 protocol, while translated fixture controls expect
exit 42. Presentation-original and the eighteen-frame image oracle are separate
checks. Native Wine requests bind their explicit API variant and seeded or
bootstrap setup. All four candidate3 native v5 controls passed with final released operations.
The old window failure and its raw lifecycle observations remain separate from
the later current-authorization adapter and fresh passing operation. Candidate3
bootstrap, bootstrap-timeout and wrong-prefix-server controls also passed with
independent release evidence. Their fresh-empty-prefix bootstrap scope does not
establish complete cold-prefix initialization or game qualification.

The CPU comparator requires all nineteen declared cases plus ordering and their
exact native-reference/source/configuration bindings. Reusing the six overlapping
seven-fixture cases requires complete final-operation, log, authority and input
joins; a pure result comparison is insufficient. A previous pass is not counted
as a fresh native run.

## Pear-owned game policy and selection

Pear owns its [development selection and game-policy guide](https://github.com/postmelee/pear/blob/codex/task56/docs/development/rosetta-free.md#select-an-isolated-development-candidate).
That Pear revision is publication-pending; the local Task #56 checkout contains
the draft until its separate public publication decision. The guide supplies the
closed local selection shape and fixed commands. The runtime owns the single
`APISession` lifecycle, live lease/current authority, captured companion provider,
final operation and independent resource release. Pear owns the explicit
`GameContext`, owned-file/snapshot admission and manual feedback/input policy.
The game branch is a separate concrete interface; a fixture context cannot grant
game execution, and saved success or inspection records are not live authority.

The current game tool producer also consumes the canonical FEX diagnostic reader
from the clean CPU source checkpoint `9c9b602c07b57a08500862abfdf62e1bac351640`.
This is the development lock's FEX tool pin, separate from selected artifact-build
`c62ed75aa6a33809ddb76c7f40aabbe4f4fbdda6` and published Stage 4 export metadata
`a8ba1cbd0148b46817842f3b7307689d4b2acbd7`. The selector verifies clean checkout
state and consumed files against the independent tool pin before imports.

Task #56 prepares/inspects this route and validates its portable wiring. Its
Stage 5.2 gate executes the required seven synthetic fixtures through the pinned
selector. It does not copy or execute the game; game/runtime qualification and
ordinary-user support remain unperformed. Future game diagnostics require exact
private inputs, fresh capacity, current authority and an independent release
check after the owned worker exits, including failure outcomes.

## Accepted evidence reuse

The accepted candidate2-to-candidate3 review retains exact original operations,
source snapshots, logs, reference data and release evidence. It does not rewrite
old candidate2 records as candidate3 runs. Component artifacts are unchanged;
common admission/header handling is stricter, while CPU execution/oracle bodies
and the canonical FEX provider remain unchanged.

| Control | Accepted evidence scope | Candidate3 observation |
| --- | --- | --- |
| Thirteen CPU-specific cases | Twelve candidate2 passes and one explicit AVX unsupported/exit-77 result | Retained semantics evidence; no new execution claimed |
| Finite ordering | Candidate2 passing operation and exact reference join | Retained unchanged-code observation |
| Six CPU-overlap cases plus rendering | Candidate2 seven-case suite remains historical | Fresh candidate3 seven-case batch passed and independently released |
| Device, 39+23 pairing, original presentation | Candidate2 passing final operations and unchanged oracles | Bounded reuse; no new operation fabricated |
| Eighteen visible presentation frames | Candidate2 unlocked retry passed; earlier failures retained | Fresh candidate3 three-cycle/eighteen-frame check passed and independently released |
| Native API, ABI, threads and window | Four candidate3 v5 final operations passed | Passed on candidate3 |
| Native bootstrap, timeout and wrong-prefix-server | Exact same-candidate four-control predecessors and fresh operation bindings | All three passed and independently released |

The capture diagnostics change only capture observation, not the original
Capture/FrameCapture bodies or verdicts. Rendering is not visible frame capture.
Current device proof is required for a new native-pairing request; a standalone
frames request may use its admitted seed without inventing a device predecessor.
Every fresh run still requires current authority, its own producer snapshot,
normal lease/deadline and independent release. Reconsider reuse after relevant
source, toolchain, configuration, feature policy or OS/GPU changes.

Earlier screen-lock metadata was observed after a failed capture control; it did
not prove lock state throughout that run or causation. The later unlocked result
is a distinct observation. No host-only capture result replaces a Wine window or
presentation oracle, and no unperformed check is marked passed.

## Portable checks and test ownership

Component source/tests belong in their forks; cross-component admission,
runner/oracle and recovery tests belong here. Selected source exports are now
present. The accepted [method map](../provenance/paired-memory-methods.json)
accounts for all 196 historical paired-memory methods: 67 exact imported bodies,
32 current contract mappings, 6 selected-compatible path mappings, 49 bounded
current contracts, 34 specific implementation-policy retirements, 7 exact
selected-input mappings and 1 selected command-construction mapping. This is a
source disposition map, not 196 new executed tests or whole old-API equivalence.
The nine protocol methods preserve the sole historical ABI2 reader; current
Wine ABI3 qualification is a separate claim.

The [mandatory-header extension](../provenance/fixture-context-import.json)
checks independently bound owner/export/private identities and actual depfile
uses. It rejects omitted or same-name shadow headers. Its retained FEX06 proof
is supplemental admission evidence, not a component rebuild. The seven selected-
only mappings and the command-construction mapping do not automatically renew
source-symbol semantics for a changed candidate. The accepted cross-repository
metadata is committed at the Stage 4 revisions above; final source-owner
acceptance remains a separate gate.

From the developer-tool checkout, the following per-directory discovery forms
cover synthetic-data and mocked runtime-operation suites. The native test
directory is explicit because it is not an importable discovery subpackage.
These grouped commands were not rerun to prepare this document and carry no new
passing test count; retain the exact source scope of the recorded portable gate:

```sh
PYTHONPATH="$FEX_SOURCE_ROOT" python3 -B -m unittest discover -s tests/fixtures -v
PYTHONPATH="$FEX_SOURCE_ROOT" python3 -B -m unittest discover -s tests/fixtures/native -v
PYTHONPATH="$FEX_SOURCE_ROOT" python3 -B -m unittest discover -s tests/cpu -v
python3 -B -m unittest discover -s tests/wine_integration -t . -v
python3 -B -m unittest discover -s tests/recovery -v
```

`FEX_SOURCE_ROOT` must identify the explicit canonical CPU source/test checkout
selected by the current fixture provenance, not the older artifact-build checkout.
The Stage 4 guarded integration receipt records 715 unique test IDs and 701
method bodies passed. The distinct build/assembly gate records 174 passing tests;
these overlapping source scopes are not added into a new total. The earlier
585-ID documentation check was collection-only at its recorded source checkpoint,
with zero tests executed. This documentation refresh reruns neither suite nor
collection. Use the actual source-bound receipts and preserve inherited/reused
method-body counts separately.

The complete build/assembly discovery forms, with the admitted immutable helper
pack explicitly bound, are:

```sh
PEAR_ASSEMBLY_SOURCE_PACK="$ASSEMBLY_HELPER_ROOT" python3 -B -m unittest discover -s tests/assembly -v
python3 -B -m unittest discover -s tests/build -v
```

These controls use temporary synthetic files and owned finite child processes;
they do not compile components, sign a runtime or launch Wine. The helper root
must contain the exact admitted source pack. See the component ownership maps
and runtime `provenance/` records for method-level limits.

The latest original source-owner review found no selected source/patch/input
changes beyond the accepted export checkpoint; that review did not transfer
source authority or execute the later diagnostics. The committed seven-fixture
checkpoint and newer Stage 4 work have different source scopes. Reuse portable results only while their recorded loaded-source
identities remain exact. Later control/recovery entrypoints are unavailable from
the historical build commit. Stage 4 source is published privately; Stage 5
publication and final source-owner acceptance are separate gates.

## Retention and recovery

Preserve each immutable pack and its inventory until all dependent builds and
recovery paths have been superseded. Keep source pins, recipe identities, exact
argv/environment, artifact hashes and required failure evidence. Do not retain a
whole historical build directory merely to conceal an undeclared dependency.

A failed component output remains an isolated diagnostic artifact. Restore a
missing exact input from its documented source or approved archive, verify its
manifest, and use a fresh output for the next attempt. Do not edit a previous
receipt, overwrite a selected runtime, change a Preview resource or reuse an
authenticated prefix. Additional deletion requires its own reviewed inventory
and authorization.


### Bounded exact-input recovery

The exercised recovery restored byte-identical local binding metadata and the
complete declared `common_headers` root: one 3,634-byte shared diagnostic header.
Missing or mismatched inputs refused. It did not restore a full object pack,
toolchain, SDK, runtime bundle, prefix or private execution state.

Run from the reviewed checkout containing `pear_runtime.recovery`. The request
pins the independent reconstruction lock, original recipe, original bindings,
component build, candidate and final operation refs. Its selected root must be a
complete declared immutable regular-file root, and its output must be fresh:

```sh
python3 -B -m pear_runtime.recovery inspect --request "$RECOVERY_REQUEST"
python3 -B -m pear_runtime.recovery restore --request "$RECOVERY_REQUEST"
python3 -B -m pear_runtime.recovery check-binding \
  --recipe "$RECIPE" --recipe-sha256 "$ORIGINAL_RECIPE_SHA256" \
  --recipe-size "$ORIGINAL_RECIPE_SIZE" --bindings "$REBOUND_BINDINGS" \
  --root common_headers --unused-output "$UNPERFORMED_OUTPUT"
```

The selected Wine recipe's independent SHA-256 is
`b78f540102228540ab0f7a84a7dd039c31a4fa5ad3f788941ecf9f4c7a813bba`, with size
5,718,534 bytes. Do not substitute a digest computed from an unreviewed changed
recipe as its own expected identity. Both request and lock schema versions require
an integer 1; boolean `true` is refused.

The command caps additional output at 64 MiB and retains a separate 6 GiB host
reserve. Completed output remains immutable; another restoration requires a fresh
request/output. `check-binding` is read-only and creates no build output. Copied
`original-bindings.json` preserves historical root values. The separate rebound
binding changes only the restored input root for future admission; it cannot
rewrite a historical build receipt's roots.

Wine's retained object/config pack exceeds this exercise's 64 MiB budget, and the
graphics pack is larger again. Those exact packs remain required. A full clean
restore or a new implementation build needs its own complete input and capacity
plan. The original build receipts, artifact lock and new developer-tool revision
remain separate evidence. No recovery command here grants execution permission.

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

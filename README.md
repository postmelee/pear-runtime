# Pear Runtime

Shared runtime contracts, diagnostic interfaces and integration tooling for
[Pear](https://github.com/postmelee/pear) and future consumers. This repository is
being established by [Pear Task #56](https://github.com/postmelee/pear/issues/56).
The package contains the existing v1/v2 contracts and shared Abort schema, plus
explicit-input Wine/FEX/graphics reconstruction and isolated candidate assembly.

## Status and boundaries

Stage 3 reconstructed the selected component artifacts. Candidate3 is a later
signed development assembly using the same component build records and artifact
refs. The recorded comparison checks all 2,824 bundle entries and 41 Mach-O
code origins; their permitted differences are signing metadata. This does not
renew historical fixture operations or grant current execution authority.

In Stage 4, all fifteen fresh candidate3 controls passed with independent release evidence:
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
[196-method ownership map](provenance/paired-memory-methods.json) has accepted
per-method dispositions. The recorded Stage 4 component checkpoints are published
on the private repositories; collaborator access is required. Owners #10, #11
and #12 accepted the exact Stage 5.2 imported scope and bounded development route.
The [source-authority record](provenance/source-cutover-task56.json) identifies
the single future editing owners, accepted commits and retained provenance. Final
documentation/report refs are recorded by the Pear Task #56 final handoff;
historical build and executed-tool revisions remain separate. This source transfer
does not activate a runtime, release retained inputs or qualify game execution.

The committed Stage 5.1 runtime tool checkpoint is
`6f0202b457f0e585c5c7621a63d203e77d07386d`. Stage 5.2 executed seven fresh
candidate3 fixture operations through Pear's selector; all passed their original
oracles and independent release checks. Its game prerequisite packet reuses eight
Stage 4 candidate3 native/bootstrap/frame operations under their original
identities, with fresh independent release observations for all fifteen selected
operations. These eight are not new Stage 5 executions. Exact game-input
inspection admitted 69 files and a 92-file producer manifest. Game-to-fixture-to-
game selection recovery changed only metadata; no game was copied or executed.
There is no gameplay, Steamworks, ordinary-user distribution, full clean restore
or complete Rosetta-independence claim.

Start with [reconstruction, controls and bounded recovery](docs/development.md), the
[assembly request and CLI](docs/assembly.md), and the
[exact selected component/recipe lock](locks/task56-reconstruction-v1.json).
Required retained compiled/generated inputs and private local configuration are
explicit prerequisites; cloning these repositories alone does not recover them.

Pear retains its app, manager, game/account policy, Preview selection and recovery
state. Component implementation belongs to the repositories below. Private
game-derived selectors, owned game data, prefixes, credentials, saves, signing
material and raw diagnostics do not belong in this repository, even while private.

## Source pins and related repositories

Contract files come unchanged from Pear
`bcd27806da5c9885cfcf40e639ae02b2c400e3c1`. Shared Abort inputs are content-pinned
from the accepted Pear diagnostic checkpoint
`951264bf5be4b9d2afb87320f5fac74778b2dd58`; generated and working-file provenance is
recorded separately in [source-import.json](provenance/source-import.json).

The component repositories currently require collaborator access. These are
upstream bases; the selected fork commits and reconstructed artifact identities
are in the lock above:

| Repository | Upstream revision selected by Task #56 |
|---|---|
| [pear-wine](https://github.com/postmelee/pear-wine) | `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf` |
| [pear-fex](https://github.com/postmelee/pear-fex) | `59f85d6b7df4eb053d2cc1b9d33411b4f31bfbaa` |
| [pear-dxmt](https://github.com/postmelee/pear-dxmt) | `7c8dee1c2d73415301ceb7d1fa810861cef4cd67` |

The historical builder is `c8887f9edaba57dffe7772cc26fd19aa9571d451`; the completed seven-fixture source
checkpoint is `c13c7030ec3b780df12373cb9e0460bbcb5b0652`. Later test/tool work does not change the selected
component build pins. [Revision roles](docs/development.md#build-pins-and-later-development-revisions)
separates those identities from the committed Stage 4 tool revision
`625fd0f97b9955e43f71cb7906ccc41d8f70853b`. Its
[Stage 4 report](mydocs/working/task_m1_56_stage4.md) is published with that
private checkpoint. The Stage 5.1 source is committed at the tool revision above;
its executed identity remains separate from the accepted Stage 5.2 handoff
commits recorded above. Earlier deferred ownership records remain historical;
they are not parallel editing authority for the accepted imported scope.

## Portable verification

Run from the repository root. Shared diagnostic tests use only Python's standard
library. Contract validators additionally need `jsonschema` and `referencing`.
The retained [dependency record](tests/contracts/dependencies.json) and
[hash-locked requirements](tests/contracts/requirements.lock) target CPython 3.14
on macOS ARM64. Their native wheel hash is platform-specific; another platform
needs a separately reviewed dependency lock, not a silent hash bypass.

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r tests/contracts/requirements.lock
.venv/bin/python -B -m unittest discover -s tests/contracts -v
.venv/bin/python -B -m unittest discover -s tests/shared -v
```

The original contract paths stay together because the validators resolve local
schema registries and v2 reuses v1 validation. The manager is not moved here.

Generate the common diagnostic header from its single schema:

```sh
python3 -B -m pear_runtime.abort_header
```

This command writes generated text to standard output and does not overwrite the
tracked header. The shared test compares generated bytes to
[`include/PearAbortObservation.h`](include/PearAbortObservation.h). Consumers
must pin this output digest alongside the runtime commit, and must not edit their
own copies. It is diagnostic formatting, separate from Wine's request ABI.

## License

Pear original code uses [GPL-3.0-or-later](LICENSE), with the existing MIT Abort
schema/generator/test terms preserved. See [NOTICE.md](NOTICE.md) for exact paths,
legacy notice handling and dependency boundaries. Component licenses and upstream
contribution policies remain separate; this import makes no upstream submission.

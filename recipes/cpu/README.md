# CPU fixture sources and development controls

The editable CPU corpus, adaptation rules, ASM wrapper generator and capture
runner belong to `pear-fex/Pear/Tests/CPU` and `pear-fex/Pear/Tools/CPU`. This
repository owns the nine boundary/ABI/ordering C/ASM sources under `tests/fex`
and `tests/cpu`, the ABI/SEH assembly generator, and runtime evidence adapters.
The provenance records are `provenance/cpu-source-import.json` and
`provenance/fixture-cpu-import.json`. Runtime CPU contract snapshots are derived
from the pinned FEX source; they are not a second editable authority.

Use a canonical absolute FEX checkout and expose it explicitly in `PYTHONPATH`.
The CPU result adapter validates that root, its reviewed commit, exact provider
bytes and canonical contracts before importing the single `effective_case`
implementation. No old worktree is inserted as a fallback.

```sh
PYTHONPATH=/absolute/path/to/pear-fex python3 -B -m pear_runtime.recipes.cpu_sources \
  --fex-root /absolute/path/to/pear-fex \
  --runtime-root /absolute/path/to/pear-runtime \
  --output /absolute/path/to/new-source-output
PYTHONPATH=/absolute/path/to/pear-fex python3 -B -m unittest discover \
  -s tests/fixtures/controls -p 'test_cpu_*.py' -v
```

Source preparation verifies the 2,270-file ASM census and reproduces the 50
selected generated/copied inputs. It does not invoke a compiler. The historical
compiler argument recipes are retained in `sources-v1.json`; the original
hosted compiler header and implicit-library inventory is incomplete. Rebuilding
new fixture PEs requires a separately admitted toolchain and renewed byte/reference
verification. A source-generation pass does not establish a fresh PE build.

The separate CPU controls driver admits exactly the original 19 CPU IDs and the
finite `ordering` case. A descriptor supplies the selected assembly/context,
immutable CPU build/reference pack, current producer manifest, explicit FEX root
and source commit, copy-tool identity, and a fresh output root. Each request has
`schema_version`, `scope: development_cpu_verification`, `descriptor_ref`,
`case_id`, `output_name`, and bounded `limits`; it cannot add game inputs or
change the fixed diagnostic options. Prepare and review those external JSON
files before executing. Keep private paths and runtime records outside Git.

```sh
PYTHONPATH=/absolute/path/to/pear-fex python3 -B -m pear_runtime.fixtures.controls.cpu_driver \
  inspect --request /absolute/path/to/cpu-request.json
PYTHONPATH=/absolute/path/to/pear-fex python3 -B -m pear_runtime.fixtures.controls.cpu_driver \
  execute --request /absolute/path/to/cpu-request.json
PYTHONPATH=/absolute/path/to/pear-fex python3 -B -m pear_runtime.fixtures.controls.cpu_driver \
  compare --request /absolute/path/to/full-corpus-index.json \
  --output /absolute/path/to/new-comparison.json
```

Inspection performs no native launch, authority command, prefix copy or lease
acquisition. Execution uses one global lease, the original owned-process
supervisor and current artifact-specific authority before/after each case.
It clones only the admitted synthetic seed into its own output, substitutes the
two selected modules, and retains cleanup and failed-operation evidence. Storage
admission preserves 6 GiB free space and budgets the full seed without assuming
APFS clone savings.

The full comparison requires all 19 ordered rows and ordering evidence. Six
explicitly admitted Stage4.1 observations may be reused only with their exact
released operation, frozen producer snapshots, runtime/PE, diagnostic options,
logs, host observations, cleanup and current-authority records. The other 13
rows and ordering require their own admitted CPU operations. AVX absence remains
`unsupported_not_exposed` with the original exit-77/event contract. Ordering
requires all 32,768 measured pairs, eight workers, nine effective thread policies
and eight checked worker retirements. These finite development checks do not
establish general CPU, game, distribution or complete late-load qualification.

For a new experiment, update the canonical component source, reviewed provider
pin and derived snapshot/recipe together. Preserve required result and execution
oracles; do not relax an expected outcome to make changed behavior pass. Retain
immutable references and failed evidence until their owners approve release.

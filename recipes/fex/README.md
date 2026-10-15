# Selected FEX reconstruction

This recipe rebuilds `Core.cpp`, `Module.cpp` and `PearFEXMemory.cpp` from the
locked `pear-fex` source, replaces exactly one member of the retained common
archive, and links a fresh development DLL. Its 81-file immutable pack contains
76 selected link operands, one archive template and four generated headers:
65,084,491 logical bytes. Lower layers are retained compiled inputs, so this is
not a complete clean source build. It does not run or qualify a game.

The selected source is the canonical editable fork. Historical D25 and later
builders supply provenance and recorded argument order; this driver does not
import or execute them. `selected-v1.json` records every argument adaptation.
The exact historical inherited environment was not captured, so the new build
uses a declared environment with locale fixed, ccache disabled and a fresh
temporary directory. Compiler verbose output, resource directory, linker trace,
dependency files and pre/post builder identities are retained in the local
receipt. `generated-headers.json` records generator/configuration ancestry for
the four preserved headers; generators are not rerun by this recipe.

Run from the `pear-runtime` checkout after binding the roots and checking the
operation's capacity:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m pear_runtime.recipes.fex \
  --recipe recipes/fex/selected-v1.json \
  --bindings /absolute/local/fex-bindings.json \
  --private-manifest /absolute/local/fex-private-input.json \
  --output /absolute/new/fex-build
```

The local bindings JSON has a `roots` object with every root named by the recipe.
Bind `fex` and `wine` to their locked Git checkouts and the six `fex_*` dependency
roots to the corresponding pinned submodule directories. Bind `inputs` to an
independently staged pack, `llvm_mingw` to the exact inventoried install,
`apple_tools` to `/usr/bin`, `system_bin` to `/bin`, and `runtime` to the runtime
checkout supplying the exact shared Abort header. Runtime's header is admitted
by content identity; it does not create a self-referential runtime commit pin.
Only the Wine-owned wire ABI header is copied into a recorded fresh export
directory. The full Wine include directory is not a cross-compiler include root,
because its Windows headers would shadow the MinGW platform headers.
There is no Apple SDK consumption in this cross-compile recipe. macOS tools and
dyld shared-cache dependencies remain explicitly identified host dependencies.
No old source directory, generated-header search tree or VFS overlay is used.

The private manifest is local JSON with `schema_version: 1`, the same absolute
`root` bound as `private`, and a single `files` row containing
`path: "PearPhaseSelection.h"`, `sha256`, and `size_bytes`. The private directory
must be outside Git. Its contents and identity never enter the public recipe;
the expanded build receipt remains local. A separately declared synthetic
selector may be bound for component experiments, with its own recipe/config
identity and expected comparisons. It cannot be represented as reproduction
of the selected private diagnostic configuration. Portable parser tests below
need no private input or proprietary data.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/build -p 'test_fex*.py' -v
```

The executor verifies all inputs and source pins, refuses active compilation
locks, and requires a fresh output directory plus a 6 GiB free-space floor and
1 GiB additional build allowance. This bounds one FEX build; shared task staging,
Wine, graphics and bundle overlap require the parent operation's separate budget.
Failures retain logs, the original error and available comparison evidence.
Neither a failure nor a successful build releases retained historical inputs.

All three new objects must be COFF ARM64EC (`0xa641`). The PE container is AMD64
(`0x8664`); the driver additionally requires a mapped executable entrypoint and
mapped CHPE metadata. It verifies that other archive members are unchanged and
stripping preserves the virtual `.text` bytes, RVA, size and flags. Raw tail
padding is reported separately: the pinned strip tool rewrites zero padding to
`0xCC`, as the original D36 files also show. Full old/new section comparisons are
retained, and PE long section names are resolved through the COFF string table.
Baseline section differences remain explicit review
items; they are not automatically attributed to debug paths. `status: passed`
means these build checks passed. The receipt retains `runtime_eligible: false`
and `game_qualified: false`; runtime assembly and affected controls are separate.

For a new source experiment, commit the component change, create a reviewed
recipe version with that source pin and current unit hashes, and bind the
external candidate lock to the new recipe/builder identities. Keep the old recipe
and receipts as provenance. Update the baseline only with an explained comparison
decision; preserve the ARM64EC/CHPE, archive, ABI, input rejection and affected
behavior oracles. The runtime driver does not hardcode the selected source hash.

Retain the immutable pack, private binding and toolchain while this recipe or a
recovery consumer needs them. Retain successful objects/DLLs and the smallest
failure evidence until artifact review, affected verification and candidate
handoff identify their remaining consumers. No cleanup is performed by this
driver, and this recipe does not authorize changing the original runtime.

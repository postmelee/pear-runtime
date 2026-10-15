# Selected Wine/DXMT graphics reconstruction recipe

`selected-v1.json` preserves the final pipeline, presentation and managed-surface source checkpoint. It compiles five units from the pinned component forks: `winemetal_unix.c`, `pear_metal_bridge.m`, the macdrv `window.c`, `pear_metal_pairing.m` and the win32u `window.c`. Exact retained archives, lower-layer objects, generated configuration and import libraries come from the staged immutable graphics pack. LLVM 15 link archives remain explicitly inventoried inputs.

```sh
python3 -B -m pear_runtime.recipes.graphics --recipe recipes/graphics/selected-v1.json --bindings /absolute/local/graphics-bindings.json --output /absolute/owned/fresh-graphics-output
python3 -B -m unittest discover -s tests/build -p 'test_graphics*.py' -v
```

Python 3, Git and the admitted Apple compiler/SDK are required. Target settings are recipe data: the selected Metal consumer uses macOS 14.0 while the selected Wine provider uses 26.5. The original Objective-C stub linker policy is retained. Compiler entrypoint spelling is also preserved: the Metal link invokes `clang++`, whose symlink target has a separate exact identity. Canonicalizing that invocation to `clang` changes implicit C++ runtime selection and is rejected. First, control links reproduce the selected object composition. Fresh changed-unit links follow, retaining the original ordering and explicit win32u-to-winemac dependency. All commands execute in new owned output, under the common executor's input, storage and exclusive-operation gates.

The manifest records exact fork source/header correspondence, historical command/producer hashes and staged-object provenance. Wine owns the typed v1/v2 provider headers; DXMT consumes pinned mirrors. DXMT owns its reverse `winemetal.h` and thunk header; Wine consumes pinned mirrors. No provider is independently edited in this build step.

Depfiles include actual headers; native linker maps expose selected objects and archives. Full maps remain hashed evidence, including binary literal bytes in their Symbols tables. A derived file preserves exactly the Object files byte range, with strict UTF-8 and table-boundary validation; no object row is skipped. Exact Mach-O dependency load commands are compared as well, including the original `libc++.1.dylib` dependency. Static checks require arm64 Mach-O and compare native text and all recorded sections, with UUID and other differences reported. This does not execute Metal, a guest fixture or Megabonk. The original typed-lease, managed-surface, ordering and pixel/readback controls remain separate required behavior verification.

Before the first compiler or linker child, the driver preserves the exact recipe, local bindings and builder source files under `builder-snapshot/` in the owned attempt output. These private snapshots, actual depfiles, linker maps, command logs and failed receipts remain available for review and recovery. An undeclared observed input fails closed and requires an explicit recipe inventory update before a fresh attempt.

Historical producers retain their original MIT notices; Wine, DXMT, DirectX and LLVM inputs retain their upstream/per-file terms and source pins. LLVM source correspondence is the retained `8dfdcc7b7bf66834a761bd8de445840ef68e4d1a` lineage. New original driver/tests carry GPL-3.0-or-later notices. Original SDK bytes, objects and local receipts are private development inputs, not public distribution artifacts. Preserve the input pack and recovery receipts until the independent candidate and retention handoff is accepted.

New experiments require new component commits and a versioned recipe/input pack with explicit changed-unit and link-operand mapping. Preserve this checkpoint and review intentional artifact differences. Extending the unit set requires a reviewed driver/test update; it never enables implicit access to an old worktree.

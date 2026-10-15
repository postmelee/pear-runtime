# Selected Wine reconstruction recipe

`selected-v1.json` declares the exact Wine fork commit, input identities, compiler and SDK closure, command order and target settings for the first independent development reconstruction. Its private local binding file supplies actual roots. No old worktree path is compiled into this recipe.

The bounded build compiles the D27 native owner and two unchanged PE string units with the selected optimization flag, then relinks declared retained lower layers. It first control-relinks selected objects. A source ownership checkout is not an assertion that all historical retained objects were built from that checkout; the original receipts and per-artifact input mappings remain separate.

```sh
python3 -B -m pear_runtime.recipes.wine --recipe recipes/wine/selected-v1.json --bindings /absolute/local/wine-bindings.json --output /absolute/owned/fresh-wine-output
python3 -B -m unittest discover -s tests/build -p 'test_wine*.py' -v
```

The command requires Python 3, Git, the exact declared LLVM-MinGW install, Apple native tools and SDK, the staged immutable pack, and the common diagnostic header. The common runtime executor verifies named roots, exact inputs, clean pinned fork source, storage reserve and the shared heavy-operation lock. Only fresh owned output is writable. The full PE object/config/tool snapshot is retained, including `version.res`, `winegcc`, `winebuild`, generated headers and the locale payload. The input pack preserves its original locale symlink; the working output materializes the identical bytes as a regular file and records that adaptation.

Wine's helper tokenizes `--cc-cmd` on spaces. This recipe passes `clang` through an explicit LLVM-MinGW-first PATH and verifies its resolved identity before launch. It does not inherit a shell PATH or substitute an unpinned host compiler. The direct compile commands still use the admitted compiler path. Unused historical configure/make variables are omitted because this driver invokes neither tool. The diagnostic flags `-v -v -save-temps -Wl,-verbose` retain child executable identities, generated spec inputs and actual COFF linker reads. Every explicit object/archive must appear in the trace; basename-only archive-member reads must resolve to a unique prior full archive read. The parser reads intact executable fields because upstream buffered stdout can interleave long argument tails.

Checks cover exact COFF bytes outside the four-byte timestamp, PE/debug timestamp normalization, whole PE equality, CHPE metadata and ARM64X machine fixups, native arm64 architecture and native text sections. Link maps and depfiles record actual direct and implicit inputs. Original optimization-experiment checks are historical evidence; this is a selected-checkpoint reconstruction, not a repeat of that experiment. Successful compilation is not host execution, game success, signing authority or distribution qualification.

The common `PearAbortObservation.h` remains a single exact input from the runtime provider; it is distinct from the Wine-exported FEX wire ABI. Common runtime header inputs use content identity, avoiding a self-referential runtime Git pin. The final candidate lock pins the builder repository commit separately.

Before the first compiler or linker child, the driver preserves the exact recipe, local bindings and builder source files under `builder-snapshot/` in the owned attempt output. These private snapshots, actual depfiles, linker maps, command logs and failed receipts remain available for review and recovery. An undeclared observed input fails closed and requires an explicit recipe inventory update before a fresh attempt.

## Provenance, licenses and recovery

The recipe retains command correspondence and SHA-256 identities for the original D27 and string builders and their receipts. Their MIT notices remain with the historical producers. Wine source remains under its upstream and per-file terms. LLVM-MinGW includes its version-specific license and complete installed input inventory; Apple SDK/tools are external prerequisites. New original driver and portable test code carries GPL-3.0-or-later notices. No game data, prefix, signing key or private selector is in this recipe.

The staged immutable pack is a required development input, not a claim of a clean toolchain bootstrap. Keep its local staging/verification receipts and historical source/object recovery references. Rebind only a complete byte/mode-matched pack and admitted tools. Public Git history alone does not recover retained compiled objects. A missing or mismatched input must refuse before compilation; no fallback to a historical worktree is permitted.

## Next development experiment

Fork source commits, target flags, input identities and historical comparison artifacts are versioned recipe data. For a new accepted source change, commit the component change, create a new recipe/input-pack version, declare the changed units and ordered link substitutions, and retain the prior recipe and receipts. Review intentional section differences instead of weakening the first reconstruction's exact-equivalence gate. A new compilation-unit category also needs a reviewed driver/portable-test extension. Potential WGI work is not part of the eight current units; its future source and link dependencies must be added explicitly, with no monorepo path fallback.

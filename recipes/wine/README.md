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

Fork source commits, target flags, input identities and historical comparison artifacts are versioned recipe data. For a new accepted source change, commit the component change, create a new recipe/input-pack version, declare the changed units and ordered link substitutions, and retain the prior recipe and receipts. Review intentional section differences instead of weakening the first reconstruction's exact-equivalence gate. A new compilation-unit category also needs a reviewed driver/portable-test extension. The original eight-unit recipe retains its declared scope. The separate WGI module recipe below now declares its own source, generation and link inputs, with no monorepo path fallback.

## WGI module correspondence

`wgi-v1.json` and `pear_runtime.recipes.wgi` reproduce the retained WGI module from its recorded 36 generator, 28 compiler and one ARM64X linker actions. The adapter first control-relinks retained objects. It then regenerates the module inputs, compiles both architecture variants and relinks the complete module. The recipe pins the independently reviewed action/input plan and the unchanged Wine source subset. A changed recipe needs an explicitly reviewed seal update in the adapter.

```sh
python3 -B -m pear_runtime.recipes.wgi --recipe recipes/wine/wgi-v1.json --bindings /absolute/private/wgi-evidence/bindings.json --output /absolute/owned/wgi-attempts/fresh-output
python3 -B -m unittest discover -s tests/build -p 'test_wgi.py' -v
```

Bindings provide `roots` for the exact Wine checkout, immutable input pack, LLVM-MinGW installation and host tools. They also provide `storage_roots` with `pack`, `attempts` and `evidence` directories. These must be separate canonical directories; the pack equals the declared input root, the attempts directory is the output parent, and the bindings file is under evidence. All retained attempts and evidence count toward the aggregate 128 MiB allocation, including failures. The driver requires a separate 6 GiB free-space reserve. Stage the pack from its exact private manifest; no old-root fallback, toolchain copy, runtime copy or prefix is needed. Public Git alone does not recover retained compiled libraries and generator tools.

The original relative `../source/` spelling, architecture settings and absence of optimization flags are preserved. The documented adaptations are explicit tool roots, the arm64 host wrapper, the pinned `clang` PATH workaround for Wine tokenization, compiler dependency files and verbose link diagnostics. Every actual compiler dependency and every linker read/child executable must be admitted. The 39 required object/archive operands are resolved against the recorded command directory for trace comparison, while their executed relative spelling stays unchanged. Wine emits its exact `./tools/winebuild/winebuild` child field relative to the recorded command directory. The WGI diagnostic adapter binds that helper to its already recorded output identity, rewrites only that field into separately hashed derived logs, and rejects any other relative child path. Original logs and executed argv remain intact. Missing evidence fails even if the DLL links successfully.

Raw compiler objects and both raw linked DLLs are retained. Only fresh working objects receive a derived four-byte COFF timestamp before the final link. PE comparison derives only bounded COFF/debug timestamp fields in memory and requires whole-file equality; RSDS, code, imports, unwind and ARM64X data are not normalized. A different raw hash is reported separately from timestamp-only equality. Failure leaves raw output, snapshots, depfiles, commands and diagnostics available, and rechecks original inputs and builder sources.

Receipts label this Task75 reconstruction only, with `runtime_eligible=false`. Completion requires `wgi_finalization_complete=true`, a successful CLI exit and an independently observed released operation; a saved status alone is insufficient. Final external storage measurement follows lease release. The reused common executor retains its historical operation-envelope name. Preparation, admission, generation, compilation, linking, comparison and lock waiting have separate recorded boundaries; no user-operable-window latency is measured. A successful reconstruction establishes only this module's correspondence. Natural WGI call observation, any behavior change, installation and game execution remain separate work.

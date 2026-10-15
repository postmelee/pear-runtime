# Runtime-owned historical memory fixtures

The sixteen files recorded in `provenance/memory-fixture-source-import.json`
are exact imports from Pear commit `951264bf5be4b9d2afb87320f5fac74778b2dd58`.
They are now editable test sources in pear-runtime; original source remains
historical evidence. This import does not compile, sign or execute a probe.

The following files retain their original MIT notices and permissions:
`ec_memory_lifecycle.h`, `ec_concurrent_lifetime.h`, and
`memory/{bitmap_selection_probe.c,metadata_budget.cpp,metadata_observation.c,
metadata_probe.c,view_capacity.c,virtual_free_provider.c}`.
See [the retained MIT text](../../LICENSES/MIT.txt).

The exact legacy files `memory/{fixture_suite.c,fixture_suite.h,
native_cooperative.c,native_owner.c,owner_launch.c,protocol.py,
wine_debug_quiet.c,wine_owner.c}` have no inline license marker. They retain
Pear's existing GPL-3.0-or-later adoption and Pear contributor attribution;
see [LICENSE](../../LICENSE) and [source notices](../../NOTICE.md). This adjacent
notice preserves the recorded bytes rather than inventing per-file MIT terms.

`memory/protocol.py` checks the historical ABI2 finite transcript contract.
The selected Wine owner supplies ABI3; passing the historical reader tests is
not current ABI3 owner validation. The canonical wire and private implementation
headers remain Wine-owned and are not copied here.

`selected_metadata_budget.inc` and `selected_view_counter.inc` are
still generation-required inputs for two unexecuted historical probe builds.
They are not missing operands of the selected reconstructed candidate.
The EC headers require their recorded actual source-lifetime integration;
they are not standalone executables. Exact dependencies and limitations are
recorded in the source-import provenance.

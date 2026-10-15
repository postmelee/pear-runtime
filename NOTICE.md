# Source notices

Original Pear code is licensed under **GPL-3.0-or-later**, except for files
with separately identified terms. The root [LICENSE](LICENSE) is copied from
Pear commit `bcd27806da5c9885cfcf40e639ae02b2c400e3c1`; its
[contributor policy](https://github.com/postmelee/pear/blob/bcd27806da5c9885cfcf40e639ae02b2c400e3c1/docs/contributing.md#source-notices)
retains existing MIT/LGPL/GPL notices and permissions.

| Paths | Terms and preservation |
|---|---|
| `runtime/contracts/`, `tests/contracts/` | Pear GPL-3.0-or-later adoption. Imported byte-for-byte, including legacy source without inline SPDX notices. This is an exact historical import, not a claim that every file meets current inline-notice policy. JSON examples remain synthetic data. |
| `pear_runtime/errors.py` | GPL-3.0-or-later. The original `Error` and `need` definitions from Pear `tools/wine/common.py` are unchanged. |
| `pear_runtime/abort_observation.py`, `pear_runtime/abort_header.py`, `tests/shared/test_abort_observation.py` | Original MIT files/functions from Pear; existing MIT terms retained. Collective Pear attribution and import namespace adaptations are recorded. See [MIT text](LICENSES/MIT.txt). |
| `include/PearAbortObservation.h` | MIT generated output of the MIT header function. Exact selected bytes are retained, including its diagnostic-payload comment. This adjacent notice deliberately leaves the frozen header identity unchanged. It contains no private selector or game bytes. |
| `pear_runtime/assembly/_transport.py` | MIT from Pear `tools/steam/signing_group.py`, adapted for owned child-process-group cleanup. Existing MIT terms retained; exact origin and lifecycle changes are recorded in [assembly provenance](provenance/assembly-import.json). See [MIT text](LICENSES/MIT.txt). |
| `pear_runtime/assembly/core.py` | GPL-3.0-or-later adapter preserving the original MIT overlay/signing-projection attribution and permissions. Source-specific inputs and transformations are recorded in [assembly provenance](provenance/assembly-import.json). |
| `pear_runtime/providers/pear_legacy/` | Exact selected Pear helper source, including historical files without inline notices; original GPL-3.0-or-later adoption and file-specific notices are retained. [Provider provenance](provenance/fixture-provider-import.json) binds all 17 original files and reviewed loaded symbols. Adjacent attribution deliberately preserves frozen source bytes; this import needs manual notice review rather than silently rewriting them. |
| `pear_runtime/fixtures/`, `tests/fixtures/` | Original pure fixture/assessment functions and tests retain their MIT or GPL terms. New original admission/producer/driver glue is GPL-3.0-or-later. The pairing module combines GPL v1 and MIT v2 material and records both terms. Original hashes, selected symbols, namespace and notice-only adaptations are in the [parent](provenance/fixture-parent-import.json), [direct](provenance/fixture-direct-import.json), [context](provenance/fixture-context-import.json), [checks](provenance/fixture-checks-import.json), [assessment](provenance/fixture-assessment-import.json), [graphics](provenance/fixture-graphics-import.json) and [controls](provenance/fixture-controls-import.json) records. See the retained [MIT text](LICENSES/MIT.txt). |
| Other new original source | GPL-3.0-or-later unless an explicit file notice states otherwise. |

[The path-specific source manifest](provenance/source-import.json) records the
original commit/checkpoint, source path, byte digest, selected function ranges,
new digest and precise transformation. A checkpoint plus content digest identifies
selected generated/working bytes; it does not claim all such bytes were in the
checkpoint Git tree. Existing authorship is not rewritten as upstream acceptance.

The shared Abort schema and generator have one proposed editable owner,
`pear-runtime`. Wine and FEX consume an exact export. The imported header is a
materialized result, not a second hand-maintained implementation. Its selected
SHA-256 is `da52c81da2051d3c255dc953f1c49758d76920f065de076de2adfa53c6f324a5`.
Final source-owner cutover remains a separate Task #56 gate.

The Python dependency record contains the dependencies' own MIT license metadata
and wheel identities. No Python dependency wheel or component binary is vendored.
Wine, FEX, DXMT, compiler and SDK notices must accompany any later imported or
distributed payload under their own terms; this skeleton does not clear them.

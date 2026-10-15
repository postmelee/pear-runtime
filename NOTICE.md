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

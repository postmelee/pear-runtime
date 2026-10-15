# Preparing and assembling a development candidate

This is the Task #56 assembly interface for the explicit development inputs
introduced in [the reconstruction guide](development.md). It assembles a fresh
candidate from one recorded parent bundle and uniquely owned component artifacts.
It does not launch Wine, a fixture, Steam or a game. A successful assembly records
`runtime_eligible`, `runtime_qualified`, `game_qualified` and
`execution_authorized_by_this_record` as false.

## Request and review

Keep the request outside Git, separate from its output parent. All reference
objects have exactly `path` (canonical absolute regular file), `sha256` (64 lower
case hexadecimal characters) and `size_bytes` (integer). References are checked
before and after consumption. Symlinks, relative paths, missing exact bytes and
implicit historical worktree defaults are refused.

The JSON request has these fields; the reference names below describe complete
reference objects, not strings to place in an executable request.

| Field | Required value |
| --- | --- |
| `schema_version` | `1` |
| `scope` | `development_candidate_assembly` |
| `inputs.parent_ref` | Exact passed diagnostic `runtime.json` and its retained bundle |
| `inputs.builds` | Build requests described below; every requested artifact role has exactly one producer |
| `inputs.roles` | Selected roles among `fex_pe`, `wine_pe`, `wine_native`, `winemetal`, `winemac`, `win32u` |
| `inputs.profile_ref` | Exact private profile; must also match the parent bundle's embedded profile |
| `inputs.helper_root` | Canonical source-only six-file helper pack with the provenance-pinned contents |
| `inputs.output_root` | Existing canonical output parent separate from all input roots |
| `inputs.name` | Fresh candidate name, lower case letters/digits/underscore/hyphen, at most 96 characters |
| `inputs.disk_floor_bytes` | Retained free-space floor, at least `6442450944` (6 GiB) |
| `expected_signing_recipe` | Complete reviewed static list of `{ "id": string, "argv": [string, ...] }` commands, each using `/usr/bin/arch -arm64` |
| `limits.whole_timeout_seconds` | Integer from 1 through 21600, covering execution admission through final checks |
| `limits.worker_log_bytes` | Aggregate Python stdout/stderr limit, 256 through 67108864 bytes |

Each `inputs.builds` entry contains exactly `ref`, `recipe_sha256`,
`source_commits` and `recipe_review`. `ref` identifies the passed component build
receipt. `source_commits` maps each Git root name to the independently reviewed
commit from the public recipe. The build receipt cannot supply its own expected
recipe or source identities. Its sibling `operation.json` must have the matching
operation ID, component-build scope and `released: true`; that exact operation
reference is retained and rechecked with the other inputs. This completed build
record is provenance, not a current execution lease.

`recipe_review` contains exactly:

```json
{
  "mode": "file_sha256",
  "public_recipe_ref": {"path": "<absolute recipe file>", "sha256": "<reviewed SHA-256>", "size_bytes": 0},
  "bindings_ref": {"path": "<absolute bindings file>", "sha256": "<reviewed SHA-256>", "size_bytes": 0},
  "private_manifest_ref": null
}
```

This is a shape example: replace every placeholder and size with reviewed facts.
Wine and graphics use `file_sha256`: the expected recipe digest must equal the
public recipe file's digest. The bindings' exact root names and paths must match
both the recipe and the receipt.

FEX uses `expanded_dict_sha256` with an additional exact `private_manifest_ref`.
Its expected `recipe_sha256` is the independently reviewed digest of the expanded
private recipe, serialized with `json.dumps(expanded_recipe, sort_keys=True)` and
UTF-8. It is **not** the public JSON file hash. Preserve that expectation from the
reviewed expansion before consuming the build receipt. The CLI verifies the
separately pinned public recipe and bindings, the explicit expanded expectation,
and the receipt's exact absolute `public_recipe`, `bindings_manifest` and
`private_manifest` refs.
It neither infers an old working directory nor substitutes a digest read from
the receipt as the expectation.

Produce the static signing list for review using the pure helper below. Supply
the independently reviewed private identity and explicit parent/output bindings;
this calculation does not query a keychain, sign, or grant authorization.

```python
from pathlib import Path
from pear_runtime import build
from pear_runtime.assembly.helpers import SourcePack, signing_helpers

helpers, _ = signing_helpers(SourcePack(helper_root))
parent = build.load(parent_runtime_json)
expected_signing_recipe = [
    {"id": ident, "argv": ["/usr/bin/arch", "-arm64", *argv]}
    for ident, argv in helpers.signing_recipe(
        Path(output_root) / candidate_name, parent["native_images"], expected_identity
    )
]
```

Review the complete list and save it in the request. During execution, current
profile/device/identity checks must resolve that same identity and regenerate
exactly that list before `codesign`. An early availability receipt is not an
artifact grant. No approval callback or saved lock-release marker is accepted.

## Subsequent controls and bounded recovery

The [developer guide](development.md#assembly-and-fixture-interfaces) describes
separate seven-fixture, graphics, native Wine and CPU contexts. Assembly success
is not a passing fixture result or current launch grant. Candidate3 retains the
same component artifacts with separately recorded signing and admission sources.
Its four native v5 controls, three bootstrap controls, fresh seven-case batch
and visible-frame observation passed, with independent release evidence.
Bounded candidate2 evidence reuse retains original operation identities and does
not fabricate a new candidate3 observation.

[Bounded input recovery](development.md#bounded-exact-input-recovery) can copy
complete small admitted input roots and original binding metadata to fresh task
output. For historical build review, copied binding JSON must retain its exact
original root values. A separate relocated binding must not be inserted into an
old build review as if the artifact had been built at its new paths.

The assembly request and local diagnostic receipts are development records with
their own explicit scopes. They are not the product `runtime_artifact` contract
and do not satisfy the Rust manager's supported-runtime admission.

## Commands and outputs

From this repository root, using Python 3.11 or newer:

```sh
python3 -B -m pear_runtime.assembly inspect --request /absolute/private/assembly-request.json
python3 -B -m pear_runtime.assembly plan --request /absolute/private/assembly-request.json
```

`inspect` and `plan` are equivalent read-only checks. They validate the request,
parent inventory and native closure, component artifacts, source pins, static
signing recipe and storage estimate. They do not create an output, acquire the
shared operation lock, change a process group, query current signing authority,
copy a bundle or execute a native command. They print a JSON plan whose authority
and execution fields remain false. This can read all recorded parent bundle bytes.

After the request and component results have been reviewed within the task's
approved assembly scope, execution is explicit:

```sh
python3 -B -m pear_runtime.assembly execute --request /absolute/private/assembly-request.json
```

The CLI owns its process group and takes a nonblocking exclusive flock on the
fixed `/private/tmp/pear-native-compilation.lock`; it does not overwrite that
file or accept an alternate lock. It revalidates inputs and available storage
under the current lease. It creates only two fresh children of `output_root`:

- `<name>/` contains the candidate, current profile/signature/closure evidence,
  command logs and `runtime.json`.
- `<name>.assembly-operation/` contains a fresh UUID-bearing `operation.json`,
  bounded worker logs, the request identity, lease observations, live interval,
  builder source refs and wall/monotonic timing.

The inner `runtime.json` records only the operation's canonical path and UUID;
the final `operation.json` records the exact `runtime_ref`. This avoids a circular
hash. Preserve **both** `runtime_ref` and `operation_ref` from the successful CLI
result as independently reviewed candidate inputs. An inner `passed: true` means
assembly checks completed; it cannot replace the final worker result.

Later current-authority admission requires the explicit reviewed operation ref:

```python
verify_current_authority(
    runtime_ref, profile_ref, helper_root, fresh_authority_output,
    operation_ref=operation_ref,
)
```

The caller must own its live execution interval and worker group. Admission
requires a final passed operation, matching UUID/output/exact runtime ref and a
released assembly lease, then rechecks its pinned bytes after fresh authority
checks. Missing, running, failed, mismatched or changed final records are refused
before native authority checks. The saved successful operation is evidence of
assembly completion; it grants no current execution permission. If the outer
worker fails after the inner runtime receipt was written, that inner receipt
remains historical evidence and cannot pass this admission.

The whole-operation timer begins after the bounded request has been parsed,
covering lock/admission, copy, replacements, current authority, signatures and
final validation. Native commands and the bundle copy each have an owned child
process group, independent command bounds and retained logs. The worker timer
unwinds those commands and kills their groups even if a leader exited first;
cleanup may additionally take the bounded five-second child-reap wait. This is
not a claim that the operating system cannot delay an I/O or scheduling event.
Python worker stdout/stderr share the requested byte limit; native command logs
have their separate recorded bound.

The storage plan includes the full logical bundle copy, positive replacement
growth, native rewrite, bounded command logs, worker logs and metadata. APFS
sharing is not assumed. The host must retain the requested floor after that
conservative additional allocation. Copying the whole bundle is deliberate:
current signatures and undeclared-file checks require an isolated complete
candidate while preserving the selected parent.

Once output admission succeeds, failures retain original errors, available logs
and false qualification claims. An unsafe request rejected before a fresh output
can be admitted creates no output receipt. A failed output is not overwritten;
review its evidence and use a fresh name for another attempt. This command does
not delete failed outputs or alter the selected parent, other runtime candidates,
private prefixes, game state or Preview resources.

Historical overlay/spec metadata is retained only as labelled provenance. It
provides no current component selection, authority or diagnostic capability.
Current runtime admission and later fixture/game verification have separate
owners and checks.

## Portable controls

```sh
PEAR_ASSEMBLY_SOURCE_PACK=/absolute/source-only/helpers-v1 \
  python3 -B -m unittest discover -s tests/assembly -v
```

The pack's six file identities are in
[`provenance/assembly-import.json`](../provenance/assembly-import.json). The controls
reuse the original profile, entitlement, signature and code-origin assertions
with synthetic inputs. They also test explicit bindings, static recipe refusal,
independent expanded-recipe expectations, current lock contention, capacity,
whole-worker timeout, bounded logs and owned child cleanup. No Apple signing or
runtime execution occurs. Process cleanup tests use a read-only `ps` query.

# SecureRollout notes

This doc is for my own reference, therefore not polished. Its a running log of design decisions and reasoning that I am updating as I build.

----

# Core Principle: Fail-Closed, Not Fail-Open
If the security check (analysis-runner/Trivy/Kyverno/Rekor) errors, times out or is unreachable, the default action is to **block promotion**, never let it through. A gate that fails open creates false confidence, which is worse than no gate.

----


# Session 1 (Kind Cluster, Argo Rollouts, AnalysisTemplate)

## What was done
- 3-node Kind Cluster (1 control plane and 2 workers) via `config.yml'
- Argo Rollouts controller + CRD installed in `argo-rollouts` namespace
- Sample `Rollout` object (`demo-rollout`) with canary steps
- Mock security check service (`hashicorp/http-echo`) simulating a pass/fail HTTP endpoint
- `AnalysisTemplate` (`mock-security-check`) using the **web-provider** polling the mock service

##Notes
1) Kind's fault-isolation limitation
 - Kind(Kubernetes in Docker) nodes are Docker containers sharing one Ubuntu kernel/CPU/RAM/disk, not separate machines. This means that:
    - It is good for testing control-plane logic, Rollout/AnalysisRun behavior, scheduling scheduling
    - but it cannot test true node-level fault isolation, a resource spike on one "node" can bleed into others as they share the same physical infra.
### Key concept: AnalysisTemplate / AnalysisRun mechanics (Web provider)
- `AnalysisTemplate` = reusable check definition. `AnalysisRun` = live instance, created when a Rollout hits an `analysis` step.
- Web provider: HTTP GET → parse JSON response via `jsonPath` → extract value into `result` → evaluate `successCondition` / `failureCondition` against it.
- This is the exact pattern analysis-runner will use — its `/check` endpoint response will be evaluated the same way, just backed by real Trivy/Kyverno/Rekor calls instead of a fixed mock value.
- Verified hands-on: real rollback triggered automatically when mock returned `"fail"` — no manual intervention. Old ReplicaSet's AnalysisRun showed `✔ Successful ✔ 3`; failing one showed `✖ Failed ✖ 1` (failed fast on first bad sample, didn't wait for remaining retries).

### Key design decision: Error vs Failed, and consecutiveErrorLimit
Argo Rollouts treats metric results as **three** states: `Successful`, `Failed`, `Error` (not just pass/fail). An unreachable endpoint / timeout / malformed response is `Error`, not automatically `Failed`.

- `consecutiveErrorLimit` (default: 4) — how many consecutive errors are tolerated before the metric is finally marked failed.
- Verified hands-on: deleted the mock Service mid-rollout → took **5** consecutive DNS-lookup failures before Argo Rollouts gave up: `"Metric assessed Error due to consecutiveErrors (5) > consecutiveErrorLimit (4)"`.
- **Why this matters for fail-closed**: Error and Failed must both result in blocked promotion / rollback — an attacker or outage causing analysis-runner to be unreachable must never be a *safer* path to promotion than an explicit fail.
- **The real risk isn't "canary sneaks past 100%"** — analysis steps block further promotion by default. The real risk is **exposure time**: traffic already being served at the current step's weight remains live and unverified for the entire duration it takes the check to resolve to a failure. Fail-closed blocks *further* promotion; it does not retroactively protect users already routed to canary pods during the uncertain window.
- **Design goal:** minimize total exposure time = `interval × consecutiveErrorLimit` (plus samples required for a genuine pass), balanced against dependency response times (Trivy/Kyverno/Rekor realistically ~10-15s) and tolerance for transient blips vs genuine outages.
- **Chosen starting values (to validate against real dependency latency in Month 2):**
  - `interval: 15s` — close to realistic Trivy/Kyverno/Rekor combined response time, without polling faster than they can respond
  - `consecutiveErrorLimit: 2` — tolerate exactly one transient blip, not two in a row
  - `count: 2` — require at least 2 genuine passing samples before trusting a result, not just 1
  - Worst-case exposure window before reacting to an error: ~30s. Revisit once real dependency latency is measured.

---

## Open questions / things to revisit
- [ ] Validate `interval`/`consecutiveErrorLimit`/`count` against actual Trivy/Kyverno/Rekor response times once analysis-runner exists
- [ ] Design analysis-runner's `/check` API contract (request/response schema)

## Session 2 — Analysis-runner request/response schema design, AnalysisTemplate args wiring

### Request schema (reasoned from first principles)
- `image_digest` — not tag. Tags are mutable pointers; a registry can silently swap what a tag points to (STRIDE tampering risk already identified). Digest is a cryptographic hash of exact content — pins to what CI actually scanned/signed. Used by both Trivy (scan target) and cosign/Rekor (verify target) — no redundant fields needed.
- `namespace` + `pod_template_hash` — NOT individual pod name (pods are ephemeral, get recreated with new names even within one revision). `rollouts-pod-template-hash` label is what Kubernetes/Argo Rollouts itself generates per-revision, stable across pod restarts within that revision. Checking one representative pod per revision is sufficient — pod specs within a revision are identical by construction (same template), so checking all 5 replicas would be redundant.

### Response schema (reasoned from first principles)
- `overall_status`: "pass"/"fail" — the ONLY field Argo Rollouts' Web provider reads via jsonPath
- `checked_digest` — echo back what was actually checked, guards against request/response mismatch bugs
- `checks: { trivy, kyverno, cosign }` — each always present (pass or fail, not just on failure — passing evidence matters too, e.g. for the "killer demo clip" and for audit trails), each with `status` + `reason` (not just pass/fail — a bare boolean gives zero triage starting point for on-call at 2am; different failing checks need completely different response playbooks)

### Argo Rollouts args-passing mechanism (learned hands-on)
- AnalysisTemplate must explicitly declare every arg it expects under `spec.args` — referencing `{{args.x}}` in metrics config without declaring `x` in `spec.args` fails with "failed to resolve {{args.x}}". This was the actual root cause of an hour+ debugging session — don't skip this declaration.
- Rollout supplies actual values when referencing the template, via three mechanisms:
  - `value: "..."` — static value (used for image-digest; real value would come from CI/GitOps pipeline writing it in the same commit as the image field, since digest isn't otherwise inferable from a running cluster object)
  - `valueFrom.fieldRef.fieldPath: metadata.namespace` — reads a field off the Rollout object itself
  - `valueFrom.podTemplateHashValue: Latest` (or `Stable`) — built-in convenience, resolves to the actual rollouts-pod-template-hash of the new (or old) ReplicaSet, no manual lookup needed

### Debugging notes (real bugs hit, worth remembering)
1. YAML key typo: `template:` vs `templates:` (plural) under an inline analysis step — caught by Kubernetes' strict decoding, failed loudly rather than silently misbehaving.
2. Argo Rollouts only runs canary steps (including inline analysis) when a genuine Stable-vs-Latest ReplicaSet distinction exists — the very first deploy to a Rollout skips steps entirely since there's nothing to canary against. `podTemplateHashValue: Latest` can't resolve without this distinction existing.
3. A rollout stuck in `Degraded`/aborted state needs an explicit `kubectl argo rollouts retry` before it'll accept further updates — a plain spec change isn't enough to unstick it.
4. Root cause of the persistent "failed to resolve {{args.pod-hash}}" error across multiple restructuring attempts: the AnalysisTemplate was missing its `spec.args` declaration block entirely (dropped during earlier live `kubectl edit` sessions). Lesson: prefer editing the source YAML file and re-applying over repeated `kubectl edit` on live objects — live edits don't automatically sync back to the file, so the file and cluster state can silently diverge.

## Session 3 — analysis-runner: Trivy + Kyverno integration (Go)

### Go fundamentals learned hands-on
- `package main` / `func main()`, Go modules (`go mod init`)
- Structs + JSON struct tags for typed request/response handling
- `os/exec` for shelling out to CLI tools (trivy, kubectl) — args passed as a slice, not a shell string, which avoids shell-injection risk since `image_digest` is externally supplied input
- Explicit `err != nil` checking as Go's core idiom — a natural fit for fail-closed design, since every failure point must be explicitly handled, nothing propagates silently
- `bytes.Buffer` + `cmd.Stdout`/`cmd.Stderr` to capture full command output including stderr (capturing only stdout initially lost the actual error reason — "exit status 1" vs the real "unable to find the specified image" message)
- `fmt.Errorf("...: %v", err)` to wrap errors with context rather than replacing them

### Trivy integration
- `exec.Command("trivy", "image", "--format", "json", ...)`, parse into structs matching Trivy's real JSON schema (`Results[].Vulnerabilities[]`, fields: `VulnerabilityID`, `Severity`, `PkgName`)
- Threshold: any single CRITICAL finding fails the whole check (strict, matches consecutiveErrorLimit=1-style fail-fast pattern elsewhere in the project; may want configurable per-environment later)
- Verified real scan against `argoproj/rollouts-demo:blue`: 5 CRITICAL, 53 HIGH — all in `stdlib` (image built with outdated Go compiler, not app-code bugs — a reminder that "vulnerable" doesn't always mean "insecure code written")
- Verified fail-closed path: nonexistent image → Trivy exits non-zero → captured via stderr → clear, specific error surfaced, not a silent pass

### Kyverno integration
- **Design point**: Kyverno's normal mode is *admission-time* blocking; project needs *re-check of already-running* pods at canary-check time → used `background: true` scanning mode instead, which continuously evaluates existing resources and writes `PolicyReport` objects queryable anytime
- **`validationFailureAction: Audit`**, not `Enforce` — deliberate: don't want Kyverno independently blocking pod creation at the K8s API level as a second, uncoordinated enforcement point outside analysis-runner's designed flow
- **Real bug caught**: initial policy used `=(runAsNonRoot): true` (conditional anchor) — this means "IF present, validate; if absent, skip (counts as pass)" — backwards from what's needed. Every pod showed 100% pass despite none setting the field, because the check was being silently skipped, not satisfied. Fixed by removing the anchor (bare field requires presence + match). **Lesson: a security policy that only checks *when a field happens to be set* can produce a false "all clear" that looks identical to genuine compliance — worth double-checking any policy's actual enforcement, not just its pass/fail dashboard.**
- **PolicyReport → Pod matching**: initially guessed at a `kyverno.io/resource.name` label (wrong — didn't exist). Correct mechanism: standard Kubernetes `ownerReferences` field on the PolicyReport object, linking back to the exact Pod (`kind: Pod`, `name: <pod-name>`) — a first-class K8s mechanism, not Kyverno-specific.
- Currently shells out to `kubectl` for both pod lookup and PolicyReport fetch (matches existing os/exec pattern) — noted as a deliberate simplification; a native Kubernetes Go client library is the more idiomatic long-term approach, planned as a future refactor.

### Open design question — error handling change
Changed Trivy's hard-error path: instead of returning HTTP 500 immediately (which would abort the whole request and never report Kyverno's result), an internal tool failure now surfaces as an explicit `checks.trivy.status: "fail"` within a normal 200 response. Tradeoff: keeps full checks breakdown visible for debugging even when one sub-check errors, but means Argo Rollouts' `Error`/`consecutiveErrorLimit` mechanism now only triggers when analysis-runner itself is completely unreachable — an internal tool failure (Trivy crashes, Kyverno unreachable) surfaces as a clean "fail" rather than an "Error" state. Need to decide if this is actually the desired behavior, or if certain internal failures (e.g., Trivy DB completely corrupted vs. a single scan failing) should still propagate as a hard error.


## Session 4 — cosign/Rekor integration; all three checks complete

### cosign integration
- Signed a real image (`securerollout-demo:blue`, pushed to own Docker Hub) using keyless (OIDC) signing — authenticated via browser, Sigstore issued short-lived cert, signature + Rekor transparency log entry created
- cosign itself warned against signing by tag rather than digest — direct external validation of the project's own "digest, never tag" threat-model decision (STRIDE: tampering)
- Verified both outcomes manually before coding: unsigned image (`argoproj/rollouts-demo:blue`) → clean `no signatures found` error, not a partial/warning state; signed image → full verification including Rekor transparency log check and cert chain validation
- Simplest of the three checks to implement — cosign's own exit code (0/non-zero) directly indicates pass/fail, no need to parse structured output and threshold like Trivy's vulnerability counts

### Note on public transparency log
Keyless signing permanently records the signer's OIDC identity (incl. email) in Rekor's public, immutable log — acceptable/intentional here since this is a public portfolio project, but worth being deliberate about for any real signing identity used in production.

### Milestone: all three checks (Trivy, Kyverno, cosign) working together
First working end-to-end response combining all three, against real signed/unsigned/vulnerable images — confirms analysis-runner's core logic is complete. Verified mixed result: Trivy fail + Kyverno fail + cosign pass → overall_status correctly "fail".

## Session 5 — Containerization, RBAC, in-cluster deployment

### Multi-stage Docker build
- Stage 1 (`golang:1.23-bookworm`): compiles the Go binary
- Stage 2 (`debian:bookworm-slim`): minimal runtime, installs trivy/cosign/kubectl CLIs, copies in ONLY the compiled binary from stage 1 via `COPY --from=builder` — Go compiler/toolchain never present in final image
- Image size: ~475MB (three bundled CLI tools account for most of this)

### Kind image loading
- Kind clusters don't share the host's Docker image cache — `analysis-runner:local` had to be explicitly loaded onto all 3 nodes via `kind load docker-image`
- Deployment uses `imagePullPolicy: Never` since the image only exists locally (not in any registry) — without this, Kubernetes defaults to trying (and failing) to pull from Docker Hub

### RBAC (least-privilege, matches original architecture doc)
- `ServiceAccount` (analysis-runner-sa) + namespace-scoped `Role` (not ClusterRole) + `RoleBinding`, all in `demo` namespace
- Role grants only `get`/`list` on `pods` and `policyreports` (`wgpolicyk8s.io` API group — a CNCF-standard schema, not Kyverno-specific) — no writes, no other resource types, no secrets access
- `serviceAccountName: analysis-runner-sa` in the pod spec is what actually mounts the ServiceAccount's token into the pod, enabling in-cluster API access — this is the concrete mechanism, not just an RBAC concept on paper

### Proof: local vs in-cluster credential behavior
- `docker run` locally (no Kubernetes context at all): Trivy + cosign worked fine (registry access only, no K8s dependency); Kyverno failed cleanly with `connection refused to localhost:8080` — kubectl's default fallback with zero configured access. Clean, honest failure — not a false pass.
- Deployed as a real pod with `analysis-runner-sa`: same Kyverno check now succeeds, using the automatically-mounted ServiceAccount token — no kubeconfig file needed anywhere, this is Kubernetes' standard in-cluster auth mechanism.
- This confirms the whole credential chain end-to-end: RBAC Role → ServiceAccount → mounted token → kubectl automatically uses it → Kyverno check succeeds with least-privilege access only.

### Milestone: analysis-runner fully running inside the cluster
First real, in-cluster (not local dev) execution of all three checks together, using genuine least-privilege RBAC — this is the actual production-shaped version of the service, not a local approximation.

### Repo structure correction
`manifests/` was briefly created inside `services/analysis-runner/` by mistake — moved to project root to match planned structure (`manifests/` = K8s resource definitions, `services/` = application source code, kept separate deliberately).

## Session 6 — End-to-end connection: real AnalysisTemplate → real analysis-runner

### The milestone
Renamed `mock-security-check` → `security-check`, pointed the real AnalysisTemplate at `analysis-runner.demo.svc.cluster.local:8081/check` (jsonPath corrected to `{$.overall_status}`, matching analysis-runner's actual top-level response field, not the mock's flat `status`).

Triggered a real canary rollout (`argoproj/rollouts-demo:yellow`) through the complete real pipeline for the first time:
Rollout → setWeight:20 → real AnalysisRun created → calls real analysis-runner pod → runs real Trivy scan + real Kyverno PolicyReport check + real cosign verify → returns overall_status: fail → Argo Rollouts automatically aborts and rolls back.

Result: `RolloutAborted: Metric "security-check" assessed Failed due to failed (1) > failureLimit (0)`

This is the project's core thesis, proven end-to-end: a canary can be automatically rolled back purely due to a security regression, independent of SLO/performance metrics — closing the exact gap identified in the original problem statement (standard canary tooling gates on performance only, allowing a version with a critical CVE, policy violation, or bad signature straight through to 100%).

### What's now real vs still simulated
- Real: Trivy scan-by-digest, Kyverno live policy check, cosign/Rekor verification, Argo Rollouts canary + AnalysisRun mechanics, RBAC/ServiceAccount-scoped in-cluster execution, automatic rollback on security failure
- Still simulated/manual: image-digest is a hardcoded placeholder (no CI pipeline yet generating it), signing/scanning happens manually rather than as part of a build pipeline, no ArgoCD GitOps sync

## Design note — handling unfixable CVEs (not yet implemented)

### The problem
Fail-closed on any CRITICAL CVE is correct as a default, but some CVEs have no available fix (Trivy `Status: affected`, `fix_deferred`, `will_not_fix` — vs `fixed`, which is genuinely actionable). A gate that blocks forever with no legitimate override doesn't improve security — it trains teams to bypass or disable the gate entirely (worse than no gate, since it creates false confidence that checks are still happening).

### Design: per-deployment allowlist ConfigMap, not a code-level bypass
- Each user/team maintains their own ConfigMap (e.g. `security-gate-allowlist`) listing explicitly accepted CVE IDs, each with a required justification, approver, and expiry/review date
- analysis-runner reads this ConfigMap at check-time; only CRITICAL findings NOT on the (non-expired) allowlist fail the gate
- Response `reason` field must explicitly state which CVEs were found vs. accepted-and-excluded — never silently hidden (same principle as the Kyverno anchor bug: a check that can silently no-op is dangerous even when the underlying decision was reasonable)

### Key guardrail: no auto-acceptance
Trivy's own `Status` field (`fixed` vs `affected`/`fix_deferred`/`will_not_fix`) is used to classify findings automatically — but "no fix available" is never auto-added to the allowlist. `will_not_fix` means "no patch coming," not "safe" — exploitability still requires human judgment (is the vulnerable code path actually reachable in how we use this package?). analysis-runner can generate a ready-to-review candidate allowlist entry (CVE ID, status, pre-filled template) to reduce tedium, but committing it to the allowlist remains a deliberate human action requiring a written justification — never automatic.

### Status: designed, not yet built. Planned for a dedicated session — touches core Trivy evaluation logic in analysis-runner and deserves focused implementation + testing, not a rushed addition.

## Session 8 — CI pipeline working end-to-end (with a real debugging lesson)

### Bug: local edits not committed
CI kept failing on stale content — traced to the Dockerfile fix existing only on local disk (`git status` showed it as modified-but-unstaged) despite believing it had been pushed. The commit that referenced the fix in ARCHITECTURE.md had gone through, but the actual Dockerfile change hadn't. **Lesson: `git status`/`git log` are the ground truth for "did this actually get pushed" — a commit message describing a change doesn't guarantee the change itself was staged and included in that commit.**

### Milestone: full CI pipeline green, GitHub-Actions-signed image
Build → push by digest → Trivy scan-by-digest (0 CRITICAL, passing) → cosign sign-by-digest, fully automated on every push to `services/analysis-runner/**`.

Verified the resulting signature's identity is the CI workflow itself, not a personal identity:
- Issuer: `https://token.actions.githubusercontent.com`
- Subject: `https://github.com/Rutuj0703/securerollout/.github/workflows/ci.yml@refs/heads/main`

This is a stronger supply-chain guarantee than manual signing: a human cannot produce a validly-signed image without it having passed through the Trivy gate first, since signing is the pipeline's last step and only runs if the scan step succeeded. Direct proof of the "who verifies the verifier" mitigation from the original threat model — trust is anchored to the pipeline's identity, not an individual's.

## Session 9 — ArgoCD GitOps wiring

### Setup friction (real debugging, worth remembering)
- `argocd login localhost:8080` via port-forward repeatedly failed with `gRPC connection not ready: context deadline exceeded`, despite plain `curl -k https://localhost:8080` succeeding (confirmed server itself was healthy/reachable). Root cause: `kubectl port-forward` can struggle with gRPC's long-lived multiplexed streaming even when simple HTTP requests work fine through the same tunnel — different connection behavior, same port.
- Fix: `argocd login --core` — bypasses argocd-server/port-forward entirely, talks directly to the Kubernetes API using existing kubectl credentials, since ArgoCD Applications are just Custom Resources under the hood. No password needed at all in this mode.
- `--core` mode then failed with `configmap "argocd-cm" not found` — traced to kubectl context having no default namespace set, so the CLI was looking in `default` instead of `argocd`. Fixed via `kubectl config set-context --current --namespace=argocd`.
- Also noticed `argocd-applicationset-controller` restarting repeatedly (6x in 20 min) — likely resource pressure from running ArgoCD's full component set on a local Kind cluster already hosting other workloads. Not yet a blocker, but a real signal about local dev resource limits worth remembering (ties back to Session 1's note on Kind's shared-kernel resource constraints).

### GitOps loop proven end-to-end
Created an ArgoCD `Application` (manual sync policy) pointing at `manifests/` in the GitHub repo, targeting the `demo` namespace. Took over management of resources originally created via manual `kubectl apply` — first sync only added ArgoCD's own tracking-id labels (no functional diff), confirming clean adoption.

Verified real drift detection + sync: changed `analysis-runner`'s replica count in Git (1→2), committed, pushed. ArgoCD's default poll interval (~3 min) means it doesn't react instantly — used `argocd app get --refresh` to force immediate re-check. Correctly showed only the Deployment as `OutOfSync` (everything else remained `Synced`), then `argocd app sync` applied it — pod count changed from 1 to 2 with zero direct kubectl commands.

## Session 10 — Allowlist mechanism for unfixable CVEs: built and verified end-to-end

### Implementation
- `security-gate-allowlist` ConfigMap (per-namespace), entries: `cve`, `reason`, `approved_by`, `expires` (YAML list)
- `loadAllowlist()`: reads ConfigMap via kubectl exec, parses YAML (gopkg.in/yaml.v3 — first external Go dependency), filters expired entries. Missing/unreadable ConfigMap → empty allowlist (fail-closed: never silently treat unreadable as "everything accepted")
- `evaluateTrivyResult()` rewritten to three-way classify CRITICAL findings: actionable (Status: fixed, not yet upgraded — always fails immediately), unfixable-and-unreviewed (fails, names the CVE, tells you to add it to the ConfigMap), unfixable-and-allowlisted (passes, but reason field explicitly names which CVEs were accepted — never silently omitted)

### Real bugs hit and fixed
1. Dockerfile builder stage only copied `go.mod`, not `go.sum` — broke once a real external dependency (yaml.v3) was added; `go build` inside Docker failed with "missing go.sum entry". Fix: `COPY go.mod go.sum ./`. Lesson: go.sum isn't optional bookkeeping — required the moment a project has any non-stdlib import, easy to forget in a Dockerfile written before that point.
2. **RBAC gap**: allowlist ConfigMap read silently failed in-cluster for a long stretch of testing — Role only granted `pods`/`policyreports`, no `configmaps` permission at all. `kubectl get configmap` inside the pod hit 403 Forbidden, `loadAllowlist` correctly fell back to empty allowlist per its fail-closed design — meaning the feature LOOKED like it wasn't working, but was actually working exactly as designed (defaulting safely closed) given insufficient permissions. Fix: added a `configmaps` rule scoped via `resourceNames: ["security-gate-allowlist"]` — least-privilege even within the new grant, not a blanket configmaps-read.
3. Disk space: accumulated Docker images/build-cache across many builds today hit 98% full, causing `kind load docker-image` to fail outright (`no space left on device`). Cleaned via `docker builder prune`, removed genuinely unrelated images (minikube kicbase, python:3.9 — neither used by this project). Kind's own node-backing volumes (`docker volume ls`, unlabeled hash names) were correctly left untouched — Docker itself refused their removal since they're actively attached to running containers, a useful built-in safety signal.

### Verified end-to-end
Real unfixable-CVE test image (rebuilt Debian-slim variant temporarily, scanned, confirmed 4 pure `affected`/`fix_deferred`/`will_not_fix` CRITICALs, no `fixed`-status ones):
- Empty allowlist → correctly failed: "4 CRITICAL CVE(s) with no available fix, not yet reviewed/accepted"
- After adding all 4 CVEs to allowlist with real justification → correctly passed: "4 CRITICAL CVE(s) present but explicitly accepted via allowlist"
- `overall_status` remained "fail" throughout, correctly — Kyverno and cosign continued failing independently, proving the three checks don't interfere with each other's results

## Session 11 — Real target-app: closing the "wrong artifact" gap

### The gap identified
Up to this point, `demo-rollout` deployed `argoproj/rollouts-demo` (Argo's public demo image) — never built, owned, or scanned by this project. Meanwhile CI only built/scanned/signed analysis-runner's own image. These were never the same artifact: the Rollout deployed one thing, CI produced another, and the `image-digest` analysis arg was a static placeholder never fed by either. "Wire CI's digest into rollout.yml" would have closed a loop connecting the wrong two things.

### Fix: built target-app, a minimal genuinely-owned workload
- Go HTTP service (`/health`, `/`), version injected at build time via `-ldflags "-X main.Version=..."` — no hardcoded version, same mechanism CI will use per-build later (Docker `ARG VERSION` → ldflags)
- Same hardened pattern as analysis-runner from the start: golang:1.25-bookworm builder → gcr.io/distroless/base-debian12 final. Verified 0 CRITICAL CVEs immediately (no repeat of analysis-runner's earlier CVE-discovery cycle, since lessons were applied upfront)
- Renamed the Rollout from `demo-rollout` → `target-app` throughout (metadata.name, selector labels, pod template labels, container name) for clarity — required delete+recreate, not an in-place rename (Kubernetes objects are identified by name)

### Proven end-to-end with the real, owned artifact
- v1.0.0: built, pushed, manually signed with cosign — deployed as `target-app`'s initial revision (first-ever deploy on a new Rollout name skips canary steps, consistent with the earlier-learned limitation)
- v1.0.1: built, pushed, deliberately left UNSIGNED — triggered via `kubectl argo rollouts set image`, with the analysis args' `image-digest` manually updated to match the new digest
- Result: real AnalysisRun ran against the real new digest, cosign check correctly failed (`no signatures found`), `RolloutAborted`, revision 2 scaled down, revision 1 (signed v1.0.0) remained stable — the project's actual thesis, proven against a real, owned, CI-buildable application for the first time, not a borrowed demo image

### Confirmed remaining gap: image-digest still manually maintained
Had to hand-edit `manifests/rollout.yml`'s `image-digest` analysis arg to match the new image tag/digest before the test worked correctly — this is exactly the manual step CI should eventually own (build target-app → capture real digest → write it into `manifests/rollout.yml`'s both the container image field AND the analysis arg → commit → ArgoCD syncs). Not yet automated.

### Debugging note
Checked rollout status once right after triggering the update and misread an intermediate/stale-looking snapshot as evidence something had gone wrong — the abort had actually already resolved correctly by then (21h-old timestamps on re-check). Lesson: a single `get rollout` call is a point-in-time snapshot, not proof of final state, especially checked shortly after triggering a change.

## Session 12 — Chaos testing: real analysis-runner outage mid-canary

Attempted deliberate chaos test (kill analysis-runner pods mid-check); accidentally deleted them slightly early, before the intended trigger. Resulting AnalysisRun (`target-app-674747b88-5-1`) captured the full real sequence: 1 successful measurement pre-outage → 3 consecutive `Error` (connection refused) measurements during the outage, exceeding the tuned `consecutiveErrorLimit: 2` → Kubernetes Deployment controller self-healed the pods (~45s) → 1 final genuine `Failed` measurement once reachable again. Rollout stayed aborted/blocked throughout — never promoted during the outage or after.

Confirms fail-closed behavior holds under a real (if accidental) outage: transient failures produce explicit errors, never silent passes; error tolerance is genuinely enforced, not just configured; recovery is handled cleanly once the dependency returns.

## Session 12 (continued) — Chaos test: Kyverno down, PolicyReport staleness gap found

Scaled `kyverno-background-controller` and `kyverno-reports-controller` to 0. Ran a real check against a genuinely live, currently-running revision (revision:1, digest sha256:4521f8d2..., hash 567cd9fb89).

**Finding: the Kyverno check succeeded and returned a real, correct violation message even with Kyverno fully down.** Root cause: analysis-runner reads the `PolicyReport` object via the K8s API server directly, not via Kyverno itself — the object persists and stays queryable indefinitely, it just stops being refreshed. The check has no mechanism to detect staleness (no timestamp check against a freshness threshold), so a report from before an outage is treated identically to a report from seconds ago.

This is a real, previously-undiscovered gap — not a bug in the sense of incorrect behavior, but a genuine correctness limitation: if a pod's live config changed while Kyverno was down, the check would keep reporting the old (now-wrong) verdict indefinitely.

## Session 12 (continued) — Real bug found via chaos testing: reasoned config never actually applied

Re-ran the Service-deletion test to compare against the earlier outage test — abort message showed `consecutiveErrorLimit (4)` (Argo Rollouts' default), not the `2` reasoned through and believed-configured earlier in the project. Checked the live AnalysisTemplate object: `consecutiveErrorLimit` wasn't set at all. Checked the source file: never written there either — `interval` had also silently reverted to `10s` instead of `15s`. The tuning conversation happened; the actual file edit never did.

Fixed via the source file (not a live edit), verified directly against the live object's spec (not just trusting `kubectl apply` succeeded — same verification discipline as the earlier missing-`spec.args` bug).

**Before/after comparison, identical failure scenario (Service deleted), same cluster:**
- Before: `consecutiveErrors (5) > consecutiveErrorLimit (4)`
- After: `consecutiveErrors (3) > consecutiveErrorLimit (2)`

Real evidence the intended exposure-time reduction is now actually enforced, not just designed. This is the core value of chaos testing demonstrated directly: verifying the deployed reality matches the reasoned design, not assuming a past decision was correctly implemented.

## Session 12 (final) — RBAC mid-flight: inconclusive, but revealed a real logging gap

Attempted to catch analysis-runner mid-check while deleting its Role, to observe an in-progress permission revocation. Timing was hard to capture precisely (same challenge as the earliest pod-kill chaos attempt). Checked analysis-runner's logs to reconstruct what happened after the fact — found they only record `"Received check request: ..."`, with no logging of the actual per-check outcome or failure reason. Root cause of a past failure currently can't be reconstructed from logs alone; it requires having captured the live HTTP response at the time.

**Real gap identified**: add structured logging of each check's actual result/reason (not just request receipt) for post-hoc diagnosability. Not yet implemented — noted as a concrete next improvement.

### Chaos-testing session summary (4 scenarios attempted, 3 conclusive)
1. Pod deletion mid-canary (accidental) — confirmed fail-closed behavior holds through a real outage + recovery
2. Kyverno fully down — found a real staleness-detection gap (PolicyReports go stale silently, no freshness check)
3. Service deleted — confirmed DNS-failure path, and in the process found `consecutiveErrorLimit`/`interval` had silently drifted from their reasoned values back to defaults; fixed and verified with before/after comparison
4. RBAC revoked mid-flight — inconclusive on the original question, but surfaced a real logging/observability gap instead

Three genuine, real findings from one session of deliberate failure-testing — this is exactly the value chaos testing is supposed to provide.

## Session 13 — Grafana dashboard: built, and a real Prometheus scrape bug found

### Built
- Instrumented analysis-runner with Prometheus metrics: `securerollout_check_results_total` (counter, labeled by tool/status), `securerollout_check_duration_seconds` (histogram), `/metrics` endpoint via promhttp.Handler()
- Minimal hand-rolled Prometheus (not full kube-prometheus-stack, to keep footprint down and understand every piece) scraping analysis-runner + Argo Rollouts' built-in metrics (`rollout_info`, `rollout_info_replicas_*`, `analysis_run_info` — free, no code required)
- Grafana, both data source and dashboard fully provisioned via ConfigMap (GitOps-consistent, no manual UI setup) — panels: rollout phase, replica counts, security check results by tool, check duration p50/p95, AnalysisRun history table, all-time totals


### Real bug found: Prometheus scraping a load-balanced Service, not individual pods
Metrics existed correctly at analysis-runner's own `/metrics`, and Prometheus's scrape target showed healthy — but PromQL queries against `securerollout_check_results_total` returned empty. Root cause: analysis-runner ran 2 replicas behind a Service; Prometheus scraped the Service DNS name, so each scrape hit a random pod with its own independent, unsynchronized in-memory counter — data was silently split and incoherent across two never-summed series.

Confirmed by direct elimination: scaled to 1 replica, data appeared immediately and correctly.

## Session 13 (continued) — Prometheus scraping and persistence fixed

### Fixed: per-pod scraping via Kubernetes service discovery
Replaced the static Service-DNS scrape target with `kubernetes_sd_configs` (role: pod), relabeled to filter only pods carrying `prometheus.io/scrape: "true"` annotations, rewriting the scrape address to each pod's own IP + declared port. Added Prometheus its own least-privilege RBAC (ServiceAccount + Role, get/list/watch on pods/endpoints/services only, namespace-scoped) to support discovery.

Added the required annotations (`prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`) to analysis-runner's pod template.

**Verified via `/api/v1/targets`**: two distinct, healthy targets for analysis-runner's two replica pods, each scraped by its own real pod IP (not the Service). 8 other cluster pods (target-app, Grafana, Prometheus itself, mock-check) correctly discovered but dropped — not annotated, so not scraped, confirming the opt-in filter works as intended, not scraping everything indiscriminately.

**Verified data correctness**: `sum(securerollout_check_results_total) by (tool, status)` now returns real, coherent aggregated totals across both replicas — the root cause from earlier (each pod's independent counter never being combined) is genuinely resolved. Scaled analysis-runner back to 2 replicas (from the earlier 1-replica stopgap).

### Fixed: Prometheus persistence
Added a PersistentVolumeClaim (2Gi, RWO) and mounted it at Prometheus's `--storage.tsdb.path`. Confirmed `Bound` status. Data now survives pod restarts — previously wiped to zero on every restart, a real limitation found and fixed within this same session.

### Both fixes verified together
Triggered a real canary check post-fix; confirmed correct aggregated pass/fail counts by tool appeared in Prometheus within the expected scrape interval, matching analysis-runner's own `/metrics` output exactly.
**Current state**: analysis-runner running at 1 replica as a stopgap — trades away redundancy for correct metrics, a known and deliberate simplification for this demo cluster, documented rather than silently accepted.

## Session 14 — Structured logging: closing the observability gap from Session 12

Replaced `log.Printf`/`log.Println` with Go's standard library `log/slog`, JSON output to stdout (Kubernetes captures automatically, no new plumbing needed — and no new dependency, `slog` has been in the stdlib since Go 1.21). Every check now logs, as real structured fields (not embedded in prose text): the incoming request, each tool's individual `status`/`reason`, and a final summary including `overall_status` and `duration_seconds`.

Verified in-cluster via `kubectl logs`: a real check produced 4 distinct, structured JSON log lines — request received, trivy result, kyverno result, cosign result, plus the final summary. This directly closes the gap found during the RBAC mid-flight chaos test (Session 12), where a past failure's actual cause couldn't be reconstructed from logs after the fact.

Bonus real data point captured along the way: full three-tool check duration is consistently 4-8 seconds in practice — comfortably within the tuned 30s `timeoutSeconds` and under the 15s `interval`, confirming real margin exists in the earlier timeout-bug fix (Session 11).

### Known limitation: Prometheus has no persistent storage
Confirmed during this session — a Prometheus pod restart (root cause not fully diagnosed, likely correlates with cluster resource pressure seen elsewhere) wiped all previously-scraped data back to zero, since no PersistentVolume is configured. Fine for demonstrating the mechanism works; not suitable as genuine historical/audit data without adding a PVC.

**Not yet fixed** — documented as a known next step: add a freshness-timestamp check on the PolicyReport (`creationTimestamp`/last-updated field) against a max-staleness threshold, failing closed if exceeded.

Restored Kyverno controllers to 1 replica each after the test; confirmed `kyverno get pods -n kyverno` shows all 4 back to `1/1 Running`.

## Session 15 — Cluster recreate (disk reclaimed), and a real ArgoCD self-management bug found and fixed

### Cluster recreate
Disk pressure (repeatedly hitting 98-100% throughout the project) finally traced to its true root cause: `/var/lib/docker/volumes` alone was consuming 55GB — Kind's 3 simulated nodes, each maintaining its own full containerd runtime, image cache, and (for the control-plane) etcd data, accumulated across months of `kind load docker-image` calls with no automatic garbage collection short of a node restart. `kind delete cluster` + recreate was the only real fix (volumes can't be selectively cleaned while nodes are live) — reclaimed the full 55GB, disk usage dropped from 98% to 55%.

Redeployed cleanly: Argo Rollouts, Kyverno, ArgoCD reinstalled from their standard install manifests; `demo` namespace recreated; local Docker images reloaded via `kind load docker-image`. Once the ArgoCD `Application` was reapplied, it automatically restored the entire `manifests/` directory (RBAC, ConfigMap, Deployment/Service, AnalysisTemplate, Rollout) in one shot — the real, tangible payoff of the GitOps investment: a fresh cluster came back to a fully working state from a single `kubectl apply`, not a manual re-run of every file.

### Real bug found: ArgoCD Application managing itself
`syncPolicy: automated` had been set locally and applied via `kubectl apply` in an earlier session, but never committed/pushed to GitHub. Because `manifests/argocd-application.yml` lives inside the very `manifests/` path the Application itself watches and syncs, ArgoCD kept silently reverting the local edit back to the last **committed** (still-manual) version on every reconcile — a genuine, structural "self-referential GitOps" pitfall, distinct from every other config-drift bug found this project (which were typos/missing fields, not a location/architecture issue). Confirmed via `git diff origin/main` showing the automated-sync change had never actually been pushed.

**Fix**: committed and pushed the real change, then ran one final manual sync (required since the live policy was still Manual — a chicken-and-egg step, since Automated can't self-apply the commit that turns it on). From that point forward, `selfHeal` is enforced with no further manual syncs needed.

**Verified selfHeal works for real this time**: manually patched `analysis-runner`'s replica count to 5 via `kubectl patch` (simulating manual drift) — ArgoCD reverted it back to Git's value (2) within 4 seconds, entirely automatically.

Good interview note: *"I found a real self-referential bug in my GitOps setup — my ArgoCD Application definition lived inside the same path it manages, so a local-only, uncommitted change to enable automated sync kept getting silently overwritten by the Application syncing itself back to the last committed version. It's a subtle failure mode specific to GitOps architectures, not a typo — the fix was recognizing that a resource watching a path shouldn't itself live inside that path without understanding the sync implications."*

## Session 15 (continued) — ArgoCD self-management deadlock, resolved

Post-recreate, discovered `manifests/monitoring/` (Prometheus, Grafana) wasn't restored at all — root cause: ArgoCD's directory source doesn't scan subfolders by default. Added `directory.recurse: true`.

This immediately broke the entire Application (`ComparisonError`, every resource showing as missing in `argocd app diff`) — root cause, found via `status.conditions`: recursive scanning parses every file under `manifests/` as a K8s manifest, and `manifests/monitoring/dashboard.json` (raw Grafana JSON, not a K8s object) failed parsing and took down the whole source, not just itself.

Attempted fix (`directory.exclude: "monitoring/dashboard.json"`, committed + pushed) hit the same self-management issue from earlier in this session: since the source was already broken, ArgoCD couldn't sync at all — including the commit meant to fix it. Genuine deadlock.

**Resolved via direct `kubectl patch application ... --type merge`**, injecting the `exclude` field into the live object, bypassing the broken Git-sync path just long enough to unblock reconciliation. Immediately cleared the ComparisonError; full monitoring stack (Prometheus + Grafana + supporting RBAC/ConfigMaps/PVC) synced successfully in one pass afterward.

**Verified**: both `prometheus` and `grafana` pods `Running`, PVC `Bound`, all resources `Synced` in ArgoCD.

Three-layer real bug: a structural GitOps pitfall (app managing its own definition) + an operational gotcha (recursive scan = parse everything) + their interaction producing a genuine chicken-and-egg deadlock, resolved by knowingly stepping outside the declarative system (direct kubectl patch) to unblock it. Strong, honest debugging narrative — each layer diagnosed with direct evidence, not guessed.`

### Remaining chaos scenarios not yet tested
- Kyverno background controller unreachable (scale to 0)
- analysis-runner Service deleted (vs. pods) — DNS-resolution-specific failure path
- RBAC revoked mid-flight
- NetworkPolicy: attempted, found Kind's default CNI (kindnet) does not enforce NetworkPolicy at all — would need cluster recreated with Calico (`disableDefaultCNI: true`) for genuine enforcement. Deferred — real cluster rebuild needed, not done yet.

### Still manual: sync policy
Currently `syncPolicy: {}` (manual) — deliberate choice to see drift detection and sync as separate, visible steps first. Automated sync (`syncPolicy.automated`) is the natural next step once comfortable with the manual flow, and pairs naturally with a future CI step that updates the image digest in `manifests/` automatically after a successful build.

### Not yet connected: rollout.yml, analysis-template.yml
These currently live at project root, not under `manifests/` — meaning ArgoCD's `securerollout-demo` Application does NOT yet manage the actual Rollout or AnalysisTemplate, only analysis-runner's own supporting resources (RBAC, Deployment, Service). Moving these into `manifests/` (or a separate ArgoCD Application) is required before GitOps genuinely covers the full system, including the canary/security-gate mechanism itself.

### Still remaining
- [ ] NetworkPolicy, mTLS, tighter RBAC review
- [ ] Grafana dashboard, chaos testing
### Remaining before this is genuinely production-shaped
- [ ] Decide/tune consecutiveErrorLimit etc. against real observed latency of a combined Trivy+Kyverno+cosign call (currently untested — likely several seconds combined, especially Trivy's DB-backed scan)
### Not yet done
- [ ] Real RBAC scoping for analysis-runner's ServiceAccount (currently running locally with your own kubectl credentials — full access, not the least-privilege Role from the original architecture doc)

to re trigger build:
echo "# trigger" >> services/target-app/README.md
git add services/target-app/README.md
git commit -m "Trigger target-app CD pipeline"
git push`

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



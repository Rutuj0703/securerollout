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

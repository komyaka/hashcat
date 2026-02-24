# STATUS.md — Recursive Autonomous Dev (Hardcoded Contract)

> **Single Source of Truth.** Все решения, результаты, причины REDO и переходы фаз фиксируются здесь.  
> **Write-zones:**  
> - Architect: SCOPE/DESIGN/INTERFACES/RISKS/EDGE CASES/PERF NOTES  
> - Coder: IMPLEMENTATION LOG + код  
> - Auditor: AUDIT FINDINGS/CHECKLIST/VERDICT  
> - Orchestrator: ORCHESTRATION/PHASE GATES

---

## ORCHESTRATION (Orchestrator only)

### Global Goal
Оптимизировать модули: **35900, 35901, 35902, 35903, 35904, 35910, 35912**  
Порядок: **35900 → 35901 → 35902 → 35903 → 35904 → 35910 → 35912**  
Правило: **следующий модуль только после `STATUS: VERIFIED` для текущего.**

### Current Focus
- Module: `_____`
- Iteration: `_____` (increment on every REDO cycle)

### Phase Gates
- Gate A (Scope): ☐ passed ☐ blocked (reason: ___)
- Gate B (Design): ☐ passed ☐ blocked (reason: ___)
- Gate C (Implementation): ☐ passed ☐ blocked (reason: ___)
- Gate D (Audit): ☐ VERIFIED ☐ REDO

### Routing Rules (REDO)
- Design flaw / ambiguity → back to **Architect**
- Bug / regression / missing tests / missing commands → back to **Coder**
- Missing acceptance criteria / unclear scope → back to **Orchestrator** then Architect

---

## SCOPE (Architect only)

### Problem Statement
- What:  
- Why:  
- Constraints (GPU arch, drivers, portability, determinism):

### In-Scope Files/Paths
- Module kernel(s):
- Related host code / parsing / dispatch:
- Tests / vectors:

### Out of Scope
- …

### Acceptance Criteria (Measurable)
1)
2)
3)

---

## RISKS (Architect only)

- Correctness risks:
- Perf risks:
- Portability risks:
- Security/robustness risks:
- Mitigations:

---

## BENCHMARK PROTOCOL (Architect → finalized, Coder executes)

> Цель — воспроизводимые цифры. Никаких “на глаз”.

### Hardware / Software Matrix (fill per run)
- GPU:
- VRAM:
- Driver:
- OS:
- Hashcat version / commit:
- Build flags:
- Power limits / clocks (if applicable):
- Notes (thermal, fan curve, etc.):

### Commands (Exact)
- Baseline benchmark command:
  - `...`
- After-change benchmark command:
  - `...`
- Correctness / self-test / vectors:
  - `...`
- Extra (profiling / occupancy tools, if used):
  - `...`

### Measurement Method
- Warmup: `__` seconds / runs
- Repeats: `__`
- Duration per run: `__`
- Report statistic: ☐ mean ☐ median ☐ best-of-N (choose one)
- Noise tolerance: `±__%`
- Required improvement target (if any): `__%`

---

## DESIGN (Architect only)

### Overview
- High-level approach:
- Why it should improve hashrate:

### Dataflow & Hotspots
- Kernel entrypoints:
- Critical loops:
- Memory access patterns:
- Branching behavior:

### Optimization Plan (Concrete Steps)
For each step:
- Change:
- Expected effect:
- Risk:
- How to verify:

1)
2)
3)

### GPU-Architecture Notes
- Register pressure / occupancy tradeoffs:
- ILP vs unroll:
- Local/shared/global memory usage:
- Vectorization / packing strategy:
- Warp/wavefront divergence considerations:

---

## INTERFACES (Architect only)

### Kernel Interface Contracts
- Inputs/outputs:
- Alignment/endianness:
- Invariants:
- Error/edge handling:

### Compatibility
- Supported backends (CUDA/OpenCL/HIP/etc.):
- Minimum GPU arch:
- Feature toggles / compile-time flags:

---

## EDGE CASES (Architect only)

- Boundary inputs:
- Length variations:
- Salt/iter variations:
- Platform-specific quirks:
- Determinism requirements:

---

## IMPLEMENTATION LOG (Coder only)

### Plan Adherence
- Implemented steps: (list numbers from DESIGN)
- Deviations: (MUST be explicit; if none, say “none”)
- Design Issues found (if any): (symptom → proposed fix → why plan fails)

### Changeset
- Files changed:
  - `path/to/file` — summary
- Functions/kernels touched:
- Key diffs summary:

### Commands Executed (with Results)
- Build:
  - Command:
  - Result: ☐ pass ☐ fail (link/log excerpt)
- Tests / vectors:
  - Command:
  - Result: ☐ pass ☐ fail
- Bench baseline:
  - Command:
  - Result:
- Bench after:
  - Command:
  - Result:

### Performance Summary (Numbers)
- Baseline: `_____` (unit, e.g., MH/s)
- After: `_____`
- Delta: `_____` (%)
- Notes on variance / stability:

---

## AUDIT FINDINGS (Auditor only)

### Correctness
- Hash math verified? ☐ yes ☐ no
- Test vectors adequate? ☐ yes ☐ no (missing: ___)
- Potential UB / overflow / endian bugs:
- Determinism issues:

### Performance Sanity
- Register pressure risk:
- Occupancy risk:
- Memory coalescing issues:
- Divergence / branching issues:
- Any likely perf regressions:

### Security / Robustness
- Bounds checks / unsafe assumptions:
- Inputs validation / unexpected behavior:

---

## CHECKLIST (Auditor only)

### Reproducibility
- ☐ Exact commands present
- ☐ Environment captured (GPU/driver/hashcat commit)
- ☐ Baseline + after numbers reported
- ☐ Variance accounted for (repeats/warmup)

### Quality
- ☐ Build clean (warnings unacceptable unless justified)
- ☐ Tests pass
- ☐ No dead code / stubs
- ☐ Changes are minimal & focused

### Spec Compliance
- ☐ Acceptance criteria met
- ☐ No silent plan changes
- ☐ Interfaces/invariants preserved

---

## VERDICT (Auditor only)

### STATUS: ☐ VERIFIED ☐ REDO

If **REDO**, provide numbered items with repro:
1) Severity: (blocker/high/med/low)  
   Location: `file:line` or `symbol`  
   Problem:  
   Repro command(s):  
   Expected vs actual:  
   Required fix:

2) …

If **VERIFIED**:
- Summary:
- Any optional follow-ups (non-blocking):

---

## MODULE TRACKER (Orchestrator updates)

| Module | State | Iteration | Baseline | After | Delta | Commands Verified | Notes |
|-------:|:------|----------:|---------:|------:|------:|:-----------------|:------|
| 35900  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35901  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35902  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35903  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35904  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35910  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |
| 35912  | ☐ todo ☐ in-progress ☐ VERIFIED | 0 |  |  |  | ☐ |  |

---

## CHANGELOG (Optional, Orchestrator or Coder)
- YYYY-MM-DD: Module ___ iteration ___ — summary

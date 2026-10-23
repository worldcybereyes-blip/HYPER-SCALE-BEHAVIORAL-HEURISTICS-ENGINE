Hyper-Scale Behavioral Heuristics Engine

Endpoint (EDR) behavioural analytics for detecting Living-off-the-Land (LotL) attacks.
Pure Python standard library. No dependencies. Runs on Windows, Linux and macOS.

---

1. The problem

Modern attackers increasingly avoid dropping custom malware. Instead they abuse tools that are already on the machine (PowerShell, `cmd`, `certutil`, Office macros, and so on), a technique known as Living-off-the-Land (LotL). Signature-based detection struggles here, because every individual binary is legitimate.

What gives the attack away is the behaviour and the chain of events: a PDF reader spawning a shell, an Office document launching encoded PowerShell, that process making an outbound connection, and then mass file modification.

This project analyses endpoint telemetry (process, network, registry and file events), reconstructs process trees, and scores them for malicious behaviour. For each tree it returns a verdict, a risk score, MITRE ATT&CK technique mapping, a step-by-step explanation and a recommended response action.

2. How it works

```
 Endpoint telemetry                Engine                              Output
 (JSON / JSONL / Sysmon-style) --> 1. Normalise events            --> verdict
                                   2. Build process trees              anomaly score (0-100)
                                   3. Extract behavioural signals      MITRE ATT&CK mapping
                                   4. (optional) compare to baseline   behavioural chain analysis
                                   5. Score + map to MITRE             recommended EDR action
```

1. Ingest and normalise. Accepts a JSON array, `{"events": [...]}`, or JSON-Lines. Native field names and Sysmon-style field names (EventID 1/3/11/12/13) are both supported.
2. Process-tree correlation. Events are grouped by parent/child relationship so the engine reasons about the *chain* of activity, not isolated events.
3. Behavioural heuristics. Each tree is checked for suspicious signals across process creation, network connections, registry queries/changes and file activity.
4. Learned baseline (optional). A frequency baseline built from your own benign telemetry adds baseline-deviation signals, so behaviour that is rare in *your* environment scores higher.
5. Scoring and mapping. Signals combine into a 0-100 score (below 40 low, 40-75 medium, above 75 high) and are mapped to MITRE ATT&CK techniques.
6. Streaming mode. In real-time mode the engine raises an alert the moment a process tree escalates to `SUSPICIOUS` or `MALICIOUS`.

Output

```json
{
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "anomaly_score": 0,
  "mitre_mapping": ["TXXXX.XXX - Technique Name"],
  "behavioral_chain_analysis": "Step-by-step breakdown ...",
  "recommended_edr_action": "TERMINATE_PROCESS_TREE | NETWORK_QUARANTINE | LOG_AND_MONITOR"
}
```

The engine recommends an action. It does not enforce one; connect the output to your EDR or SOAR platform to act on it.

3. Tools and technologies

| Area | Details |
|---|---|
| Language | Python 3.8+ (3.10+ recommended) |
| Dependencies | None (standard library only) |
| Input formats | JSON, JSON-Lines, Sysmon-style events |
| Detection approach | Behavioural heuristics + frequency baseline |
| Threat framework | MITRE ATT&CK |
| Testing | Python `unittest` (13 automated tests) |
| Reporting | `reportlab` (optional, only to rebuild the PDF report) |

4. Repository structure

```
HyperScale_EDR_Engine/
  run.py                 entry point (demo / analyze / stream / baseline / test)
  run_demo.bat           one-click demo on Windows
  run_demo.sh            one-click demo on Linux/macOS
  requirements.txt
  HOW_TO_RUN.txt         detailed run and troubleshooting guide
  edr_engine/            the engine package
  samples/               synthetic telemetry (8 scenarios) + example baseline
  tests/                 automated tests
  docs/                  Project_Report.pdf, build_report.py
```

5. Reproduce the demonstration

Use `py -3` on Windows and `python3` on Linux/macOS.

```bash
1. Run the 8 sample scenarios (table of verdict, score, action)
python run.py demo

2. Same, with the full JSON verdict for each
python run.py demo --json

3. Analyse one file
python run.py analyze samples/04_malicious_pdf_to_ransomware.json

4. Analyse with a learned baseline
python run.py analyze samples/03_suspicious_office_encoded_ps.json --baseline samples/baseline_model.json

5. Show every suspicious process tree with signals and score breakdown
python run.py analyze mylog.json --all --verbose

6. Real-time mode (alerts as trees escalate)
python run.py stream events.jsonl

7. Build a baseline from your own benign telemetry
python run.py baseline --build my_benign_events.json --out my_baseline.json

8. Run the automated tests (expected: "Ran 13 tests ... OK")
python run.py test
```

Use as a library:

```python
from edr_engine import analyze, Baseline
from edr_engine.cli import load_events

result = analyze(load_events("samples/04_malicious_pdf_to_ransomware.json"))
print(result["verdict"], result["anomaly_score"])
```

6. Evidence

| Claim | How to verify |
|---|---|
| Engine classifies a range of attack and benign scenarios | `python run.py demo` runs 8 sample scenarios and prints verdict, score and action for each |
| Multi-stage chains are detected end to end | `samples/04_malicious_pdf_to_ransomware.json` models a malicious PDF leading to ransomware-style behaviour |
| Baseline improves detection of unusual behaviour | Compare `analyze samples/03_suspicious_office_encoded_ps.json` with and without `--baseline` |
| Every verdict is explainable | `--verbose` shows the process tree, signals and score breakdown |
| Code behaves as specified | `python run.py test` runs 13 automated tests |
| Full write-up | `docs/Project_Report.pdf` |

> Add before publishing: a screenshot of the `demo` output table and a screenshot of the passing test run. Place them in `docs/images/` and embed them here. Visible results are the strongest evidence for a recruiter.

7. Limitations

- Synthetic data. The sample telemetry is synthetic, and the IP addresses are RFC 5737 documentation addresses. Results on the samples do not prove real-world detection rates.
- Heuristics, not machine learning. Detection uses behavioural rules plus a frequency baseline. It is not a trained deep-learning model, and weights and baselines need tuning for each environment.
- No enforcement. The engine recommends actions only. It does not terminate processes or quarantine hosts.
- Telemetry-dependent. Events must be supplied in time order, and detection quality depends on the visibility of the telemetry source (for example, a well-configured Sysmon).
- Offline analysis. It only reads telemetry files you give it. It does not collect data from, or modify, the machine it runs on.
- Not benchmarked at scale. Treat the "hyper-scale" name as a design goal. No throughput benchmarks are included.

8. Intended use

This is a defensive analysis tool for learning and for SOC/detection-engineering use. It does not execute, collect or alter anything on the host.

9. Author

Rushikesh Kulkarni: aspiring SOC Analyst (Pune, India):  worldcybereyes@gmail.com


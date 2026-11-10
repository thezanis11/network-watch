# Dataset, evaluation and incident semantics

## Acquisition and source quality

The official Zenodo record 21027042 exposes original labeled Zeek logs, labeling rules and documentation under CC BY 4.0. The downloader verifies each selected file against the record's MD5 and stores source URLs, DOI, size and license. Raw packet captures and executables are not required.

The documentation declares 286,704 flows. The checksum-verified labeled log files contain 286,702 parsed data rows, including 28,225 rather than 28,227 in malware-2. `data_quality.json` records this discrepancy, per-capture labels, duplicate UID counts and purges. No rows are invented to make totals match. Zero duplicate UIDs within a source capture were observed.

## Fixed split

| Source | Use |
|---|---|
| malware-1 | training |
| portscan-1 | training |
| portscan-2 | validation |
| malware-2 | test |
| portscan-3 | test |
| benign-user-traffic-1 | chronological 60/20/20 quantile partitions |

The benign recording has 300-second exclusions on both sides of each boundary. A total of 572 rows are purged. History state is reset for every capture/partition. Other captures are kept intact. Labels marked Background or unknown are not negative examples: they remain context but are excluded from binary fitting/evaluation.

The benign recording is dominated by Background labels, not known-benign labels. Normal traffic also exists inside the malware captures. Therefore filenames are not used as flow labels, and splitting or labeling solely by capture name would be wrong.

## Causal features

The adapter approximates observation availability by connection start plus duration. At that time, the current completed flow's duration, byte totals, packet totals, connection state and protocol/service may be observed. A host history contributes only earlier observations in a 60-second window. It tracks flow count, unique ports and destinations, failure fraction and byte imbalance. A bounded per-peer interval history contributes regularity measures.

The feature matrix excludes source/destination addresses, UID, absolute timestamps, labels, detailed labels and capture identifiers. The current destination port contributes only coarse well-known/high-port flags, not a raw numeric port. Addresses are used to define history keys and grouping, not as learned identifiers. Features are created before the current event updates history.

Sorting by approximate completion time is necessary because conn logs' flow-start order does not establish when full byte/duration measurements became available. This is still an approximation: original collector ingestion timestamps and streaming update behavior are not available.

## Detectors and calibration

- Explainable rules: vertical/horizontal scan patterns from fan-out and failures; periodic small flows from peer interval variation; optional upstream Suricata signature evidence.
- Logistic Regression: standardized features, regularization C=1, balanced class weighting.
- Isolation Forest: fit on known-benign training flows only.
- Random Forest: 180 trees, minimum five samples per leaf, balanced subsampling, fixed seed 42.
- Random Forest without history: same supervised estimator with history and peer-time features removed.
- Constant benign and malicious baselines expose the class imbalance.

Balanced thresholds maximize validation F1. A second operating point uses the 99th percentile of benign validation scores. The model is selected by validation F1 only; constant baselines are descriptive references, not deployment candidates. Even the normal-only fitted model uses attack validation labels for its balanced operating point. No test score is used in automatic model or threshold selection.

The test was inspected during exploratory development, including the addition of imbalance diagnostics. The final result is not claimed to be a blind external audit. The better test score of the history-free forest does not justify silently changing the selected model after seeing the test.

## Flow metrics versus incidents

Flow metrics report precision, recall, F1, average precision, ROC-AUC, balanced accuracy, MCC, false-positive counts and rates. Single-class captures do not have a defined benign false-positive rate or two-class balanced accuracy. Per-capture results are retained because the scan is much larger than the malware capture. No confidence interval based on random independent-flow bootstrap is claimed.

Alerts are grouped by capture, source host and evidence motif with a maximum 120-second inter-alert gap. The algorithm never consults labels to decide grouping. After grouping, an incident is annotated as containing a labeled attack, labeled-benign-only, or unscored because unknown traffic is present.

Reference episodes are contiguous labeled malicious flows from the same source host and detailed behavior, split by gaps above 300 seconds. They measure detection coverage and availability-based delay. They are not expert-confirmed incidents. Host hashes in exported incidents are deterministic pseudonyms, not a claim of irreversible anonymization.

## Scope boundaries

No live traffic interception, active network scanning, blocking, malware execution or production SIEM deployment is implemented. EVE input supports flow and alert events but does not fully deduplicate two views of one connection. Real environments need independent validation, calibrated policies, known collector timing, handling of out-of-order streaming data, operational alert review and data-retention controls.

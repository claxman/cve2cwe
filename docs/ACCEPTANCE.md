# Acceptance bar

Status: final

Prepared: 2026-11-24T14:53:41Z

## Candidate

The candidate is the 2-epoch set (candidate_e2-seed1, candidate_e2-seed2, candidate_e2-seed3).
Dev mean accuracy, 1 epoch: 0.8852241150175185.
Dev mean accuracy, 2 epochs: 0.8882445330433733.
The candidate is the length with the higher mean dev accuracy over its three seeds. A tie goes to 1 epoch.
Chosen length: 2 epochs.
Shipped checkpoint: candidate_e2-seed1 (median dev accuracy 0.8880028996013049).

## Champion

Champion: tfidf_svm.
Run id: 20261124T114405Z-5b864cd.
Test accuracy: 0.7268314210061783.

## Gates

G1 gain: the mean test accuracy over the three seeds is at least 0.7468314210061783 (champion accuracy 0.7268314210061783 plus 0.02).
G2 noise: for every seed, the lower bound of the 95% paired-bootstrap interval of candidate minus champion is above 0.
G3 must-pass: every seed is at least 0.98 accurate on the pinned set.
G4 validity: the invalid rate is at most 0.005 for every seed.

## Must-pass set

Count: 868.
sha256: ae51d10f8d1adaee0ac10b9ae499399a396bd7b34077c61fe01d353698c76075.
The sha256 is of the canonical JSON object with keys count and cve_ids.
File: data/processed/must_pass.json.

## Routing thresholds

Lowest dev confidence at which records at or above it are at least 95% accurate, and the same for 97%. Coverage is the share of all dev records at or above the threshold.

candidate_e2-seed1, dev run 20261124T134546Z-d5303a1:
- at_0.95: threshold 0.7455690224895739, accuracy 0.9501066098081024, coverage 0.8499456324755346, n 2345.
- at_0.97: threshold 0.8571389794337373, accuracy 0.9703016241299304, coverage 0.7810801014860457, n 2155.

tfidf_svm, dev run 20261124T114403Z-5b864cd:
- at_0.95: threshold 0.5249350643900713, accuracy 0.9502304147465438, coverage 0.7865168539325843, n 2170.
- at_0.97: threshold 0.9941718718366617, accuracy 0.9704241071428571, coverage 0.6495106922798115, n 1792.

## Serving

Gate runs use the deterministic serving mode in D1: --enforce-eager, --no-enable-prefix-caching, and one request at a time.

No fine-tuned checkpoint has been evaluated on the test split before this commit. llm_eval.py refuses to do so until this file is final and committed.

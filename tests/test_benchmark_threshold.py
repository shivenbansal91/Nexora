import numpy as np
from detection.benchmark_cicids import calibrate_threshold


def test_calibration_respects_budget_and_tied_scores():
    scores = np.array([.9, .8, .8, .7, .6])
    labels = np.array([1, 1, 0, 0, 0])
    threshold, f1 = calibrate_threshold(scores, labels, max_fpr=0)
    assert threshold == .9 and f1 > 0
    assert not (scores[labels == 0] >= threshold).any()
    threshold, f1 = calibrate_threshold(np.array([.8, .8]), np.array([1, 0]), max_fpr=0)
    assert threshold > .8 and f1 == 0

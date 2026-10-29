#!/usr/bin/env python3
"""Evaluate local ONNX prompt-injection candidates without training or networking."""

import argparse
import hashlib
import json
import statistics
import time
from pathlib import Path


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int(len(ordered) * fraction + .999) - 1))]


class Candidate:
    def __init__(self, directory):
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoTokenizer

        self.np = np
        self.directory = directory
        manifest_path = directory / "model-manifest.json"
        self.manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        for relative, expected in self.manifest.get("sha256", {}).items():
            path = directory / relative
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
            if actual != expected.lower():
                raise RuntimeError(f"artifact digest mismatch: {path}")
        models = sorted(directory.glob("*.onnx")) or sorted((directory / "onnx").glob("*.onnx"))
        if len(models) != 1:
            raise RuntimeError(f"expected exactly one ONNX model under {directory}")
        self.tokenizer = AutoTokenizer.from_pretrained(str(directory), local_files_only=True)
        self.session = ort.InferenceSession(str(models[0]), providers=["CPUExecutionProvider"])

    def score(self, text):
        encoded = self.tokenizer(text, return_tensors="np", truncation=True, max_length=512)
        names = {item.name for item in self.session.get_inputs()}
        feeds = {key: value for key, value in encoded.items() if key in names}
        started = time.perf_counter()
        logits = self.session.run(None, feeds)[0][0]
        latency_ms = (time.perf_counter() - started) * 1000
        shifted = logits - self.np.max(logits)
        probabilities = self.np.exp(shifted) / self.np.exp(shifted).sum()
        return float(probabilities[1]), latency_ms


def load_dataset(path):
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row.get("text"), str) or row.get("label") not in (0, 1):
                raise ValueError(f"invalid JSONL row {line_number}; expected text and label 0/1")
            rows.append(row)
    if not rows or not {row["label"] for row in rows} == {0, 1}:
        raise ValueError("dataset must contain both benign (0) and injection (1) rows")
    return rows


def evaluate(directory, rows, threshold):
    candidate = Candidate(directory)
    predictions, latencies = [], []
    for row in rows:
        score, latency = candidate.score(row["text"])
        predictions.append((row["label"], score >= threshold))
        latencies.append(latency)
    tp = sum(label == 1 and prediction for label, prediction in predictions)
    fn = sum(label == 1 and not prediction for label, prediction in predictions)
    fp = sum(label == 0 and prediction for label, prediction in predictions)
    tn = sum(label == 0 and not prediction for label, prediction in predictions)
    recall = tp / (tp + fn) if tp + fn else 0
    precision = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    fpr = fp / (fp + tn) if fp + tn else 1
    p95 = percentile(latencies, .95)
    return {
        "model_id": candidate.manifest.get("model_id"),
        "revision": candidate.manifest.get("revision"),
        "threshold": threshold, "samples": len(rows), "recall": recall,
        "precision": precision, "f1": f1, "false_positive_rate": fpr,
        "latency_ms": {"mean": statistics.fmean(latencies), "p95": p95,
                       "p99": percentile(latencies, .99)},
        "eligible": recall >= .90 and fpr <= .01 and p95 <= 250,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Held-out JSONL with text and label (0/1)")
    parser.add_argument("candidates", type=Path, nargs="+", help="One to three local model directories")
    parser.add_argument("--threshold", type=float, default=.90)
    args = parser.parse_args()
    if not 1 <= len(args.candidates) <= 3:
        parser.error("provide one to three candidates")
    rows = load_dataset(args.dataset)
    results = [evaluate(path, rows, args.threshold) for path in args.candidates]
    eligible = sorted((result for result in results if result["eligible"]),
                      key=lambda result: result["f1"], reverse=True)
    print(json.dumps({"results": results, "selected": eligible[0] if eligible else None}, indent=2))
    raise SystemExit(0 if eligible else 2)


if __name__ == "__main__":
    main()

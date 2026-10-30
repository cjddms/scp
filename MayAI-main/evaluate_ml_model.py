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
    with path.open(encoding="utf-8-sig") as stream:
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


def metrics(scored, threshold):
    """scored: [(row, score)] -> confusion counts and rates at one threshold."""
    tp = sum(row["label"] == 1 and score >= threshold for row, score in scored)
    fn = sum(row["label"] == 1 and score < threshold for row, score in scored)
    fp = sum(row["label"] == 0 and score >= threshold for row, score in scored)
    tn = sum(row["label"] == 0 and score < threshold for row, score in scored)
    recall = tp / (tp + fn) if tp + fn else 0
    precision = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    return {"samples": len(scored), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": round(recall, 4), "precision": round(precision, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4)}


def grouped(scored, key, threshold):
    groups = {}
    for row, score in scored:
        groups.setdefault(row.get(key, "-"), []).append((row, score))
    return {name: metrics(items, threshold) for name, items in sorted(groups.items())}


SWEEP = (.50, .70, .80, .85, .90, .95, .97, .99)


def evaluate(directory, rows, threshold, details=False):
    candidate = Candidate(directory)
    scored, latencies = [], []
    for row in rows:
        score, latency = candidate.score(row["text"])
        scored.append((row, score))
        latencies.append(latency)
    overall = metrics(scored, threshold)
    p95 = percentile(latencies, .95)
    result = {
        "model_id": candidate.manifest.get("model_id"),
        "revision": candidate.manifest.get("revision"),
        "threshold": threshold, **overall,
        "latency_ms": {"mean": statistics.fmean(latencies), "p95": p95,
                       "p99": percentile(latencies, .99)},
        "eligible": overall["recall"] >= .90 and overall["false_positive_rate"] <= .01 and p95 <= 250,
    }
    if details:
        result["by_surface"] = grouped(scored, "surface", threshold)
        result["by_lang"] = grouped(scored, "lang", threshold)
        result["by_category"] = grouped(scored, "category", threshold)
        result["sweep"] = {
            f"{value:.2f}": {surface: {k: m[k] for k in ("recall", "false_positive_rate", "f1")}
                             for surface, m in grouped(scored, "surface", value).items()}
            for value in SWEEP}
        result["errors"] = [
            {"id": row.get("id"), "kind": "false_positive" if row["label"] == 0 else "missed",
             "surface": row.get("surface"), "category": row.get("category"),
             "score": round(score, 4), "text": row["text"][:120]}
            for row, score in sorted(scored, key=lambda item: -abs(item[1] - item[0]["label"]))
            if (score >= threshold) != (row["label"] == 1)]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Held-out JSONL with text and label (0/1)")
    parser.add_argument("candidates", type=Path, nargs="+", help="One to three local model directories")
    parser.add_argument("--threshold", type=float, default=.90)
    parser.add_argument("--details", action="store_true",
                        help="add per-surface/lang/category metrics, a threshold sweep and misclassified rows")
    args = parser.parse_args()
    if not 1 <= len(args.candidates) <= 3:
        parser.error("provide one to three candidates")
    rows = load_dataset(args.dataset)
    results = [evaluate(path, rows, args.threshold, args.details) for path in args.candidates]
    eligible = sorted((result for result in results if result["eligible"]),
                      key=lambda result: result["f1"], reverse=True)
    print(json.dumps({"results": results, "selected": eligible[0] if eligible else None},
                     indent=2, ensure_ascii=False))
    raise SystemExit(0 if eligible else 2)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fine-tune Prompt Guard 2 on MCP samples. Run with torch + transformers installed.

Rows from one semantic family (id ...-a005-19) are near-copies, so the validation
split holds out whole families. The final test set never enters this script.
"""

import argparse
import json
import random
import re
from pathlib import Path

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

FAMILY_RE = re.compile(r"-([ab]\d+)-\d+$")


def load_rows(path):
    with path.open(encoding="utf-8-sig") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    for row in rows:
        if not FAMILY_RE.search(row["id"]) or row["label"] not in (0, 1):
            raise ValueError(f"unexpected row: {row['id']}")
    return rows


def split_by_family(rows, fraction, seed):
    """Hold out a share of families per label; returns (train, validation)."""
    families = {0: set(), 1: set()}
    for row in rows:
        families[row["label"]].add(FAMILY_RE.search(row["id"]).group(1))
    rng = random.Random(seed)
    held_out = set()
    for names in families.values():
        ordered = sorted(names)
        rng.shuffle(ordered)
        held_out.update(ordered[:max(1, round(len(ordered) * fraction))])
    train = [row for row in rows if FAMILY_RE.search(row["id"]).group(1) not in held_out]
    validation = [row for row in rows if FAMILY_RE.search(row["id"]).group(1) in held_out]
    return train, validation


def normalize_text(text):
    return re.sub(r"\W+", " ", text.lower()).strip()


def unique_extra_rows(extra, existing):
    """Drop rows repeating an earlier text. Extra rows are train-only because
    their shared templates would inflate validation scores."""
    seen = {normalize_text(row["text"]) for row in existing}
    unique = []
    for row in extra:
        key = normalize_text(row["text"])
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def freeze_lower_layers(model, trainable_layers):
    """Train only the classifier and the top encoder layers: faster on CPU and
    less likely to forget what the base model already detects."""
    for parameter in model.deberta.embeddings.parameters():
        parameter.requires_grad = False
    layers = model.deberta.encoder.layer
    for layer in layers[:len(layers) - trainable_layers]:
        for parameter in layer.parameters():
            parameter.requires_grad = False


def batches(rows, size, rng=None):
    order = list(rows)
    if rng:
        rng.shuffle(order)
    for start in range(0, len(order), size):
        yield order[start:start + size]


def encode(tokenizer, batch, max_length):
    return tokenizer([row["text"] for row in batch], return_tensors="pt", padding=True,
                     truncation=True, max_length=max_length)


@torch.no_grad()
def evaluate(model, tokenizer, rows, max_length, batch_size, threshold):
    model.eval()
    tp = fn = fp = tn = 0
    for batch in batches(rows, batch_size):
        scores = torch.softmax(model(**encode(tokenizer, batch, max_length)).logits, -1)[:, 1]
        for row, score in zip(batch, scores.tolist()):
            detected = score >= threshold
            tp += row["label"] == 1 and detected
            fn += row["label"] == 1 and not detected
            fp += row["label"] == 0 and detected
            tn += row["label"] == 0 and not detected
    return {"threshold": threshold, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": round(tp / (tp + fn), 4) if tp + fn else 0,
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("train", type=Path)
    parser.add_argument("base_model", type=Path, help="Local Prompt Guard 2 directory with safetensors")
    parser.add_argument("output", type=Path)
    parser.add_argument("--extra-train", type=Path, help="Additional training-only JSONL")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--trainable-layers", type=int, default=2)
    parser.add_argument("--validation-fraction", type=float, default=.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-steps", type=int, default=0, help="Stop early; for smoke tests")
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    rows = load_rows(args.train)
    train, validation = split_by_family(rows, args.validation_fraction, args.seed)
    if args.extra_train:
        extra = load_rows(args.extra_train)
        unique = unique_extra_rows(extra, rows)
        train += unique
        print(f"extra={len(extra)} unique={len(unique)} "
              f"benign={sum(r['label'] == 0 for r in unique)} attack={sum(r['label'] == 1 for r in unique)}",
              flush=True)
    print(f"train={len(train)} validation={len(validation)}", flush=True)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, local_files_only=True)
    freeze_lower_layers(model, args.trainable_layers)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    optimizer = torch.optim.AdamW((p for p in model.parameters() if p.requires_grad), lr=args.lr)

    rng = random.Random(args.seed)
    step = 0
    finished = False
    for epoch in range(args.epochs):
        model.train()
        for batch in batches(train, args.batch_size, rng):
            inputs = encode(tokenizer, batch, args.max_length).to(device)
            labels = torch.tensor([row["label"] for row in batch], device=device)
            loss = model(**inputs, labels=labels).loss
            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
            step += 1
            if step == 1 or step % 20 == 0:
                print(f"epoch={epoch + 1} step={step} loss={loss.item():.4f}", flush=True)
            if args.max_steps and step >= args.max_steps:
                finished = True
                break
        if finished:
            break

    if device == "cuda":
        model.to("cpu")
    report = [evaluate(model, tokenizer, validation[:16] if args.max_steps else validation,
                       args.max_length, args.batch_size, threshold) for threshold in (.5, .9)]
    print(json.dumps(report, indent=2), flush=True)
    args.output.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    (args.output / "validation-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()

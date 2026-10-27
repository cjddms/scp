# MayAI MCP Tool Poisoning ML Deployment

## Implemented boundary

- Only MCP `tools/list` and `tools/call` responses are classified.
- `tools/list` scans tool title/description, nested input/output schema descriptions, annotations and metadata.
- `tools/call` scans text blocks, embedded text resources, resource-link descriptions, structured content and metadata.
- The classifier is advisory. Request policy remains authoritative and the first deployment stays in `MONITOR`.
- Unsupported languages, unavailable inference and partial inspection are passed through with explicit findings.

## Offline model gate

No model is downloaded at runtime and MayAI does not train a model. Compare no more than three public, fine-tuned ONNX candidates on a held-out response dataset. A candidate is eligible only when attack recall is at least 90%, benign false-positive rate is at most 1%, and 512-token CPU latency on the deployment host is at most 250 ms at p95. Among eligible candidates select the highest F1 score.

Run `python evaluate_ml_model.py heldout.jsonl candidate_dir [candidate_dir ...]`. The evaluator accepts one to three local candidates, verifies their manifests, emits comparable metrics, selects the eligible candidate with the highest F1, and exits with status 2 when none qualify.

The initial candidate is `protectai/deberta-v3-base-prompt-injection-v2`. It is English-only and archived, so it is not considered production-approved until it passes the gate. Pin the chosen repository revision and populate SHA-256 values in `model-manifest.json` from independently verified artifacts.

## Activation

1. Install `requirements-ml.txt` in the MayAI virtual environment.
2. Place the tokenizer files and one ONNX model under `models/prompt-injection`.
3. Copy `model-manifest.example.json` to `models/prompt-injection/model-manifest.json`, replace every placeholder with the verified digest, and keep the configured model id and revision aligned with `MayAI.py`.
4. Run `python MayAI.py --selftest`, start the management API, and verify `/api/ml/status` reports `loaded: true` after the first eligible MCP response.
5. Operate in `MONITOR` for at least two weeks. Review false positives, unsupported-language counts, partial inspections, unavailable events and p95/p99 latency.
6. Enable `ENFORCE` only after the acceptance gate is met, and only through an explicit response DENY policy for `TOOL_DEFINITION_INJECTION` or `TOOL_RESULT_INJECTION`.

## Operational defaults

- Classification labels: `BENIGN`, `SUSPICIOUS`, `INJECTION`.
- Threshold version: `v1-fpr-1pct`; provisional thresholds are 0.70 and 0.90 and must be replaced by held-out calibration values before enforcement.
- Chunk size: 510 payload tokens plus model special tokens; maximum 16 chunks per response.
- Timeouts: 500 ms per chunk and 2 seconds per response.
- Audit storage contains hashes, redacted previews, paths, model metadata and latency, never full extracted text.
- Image OCR, audio transcription and request-argument propagation analysis are out of scope.

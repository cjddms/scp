# MayAI MCP Prompt-Injection ML Deployment

## Implemented boundary

ML classification covers all three MCP component types:

| Method | Scanned text | Finding |
|---|---|---|
| `tools/list` | tool title/description, nested input/output schema descriptions, annotations, metadata | `TOOL_DEFINITION_INJECTION` |
| `tools/call` | text blocks, embedded text resources, resource-link descriptions, structured content, metadata | `TOOL_RESULT_INJECTION` |
| `resources/list`, `resources/templates/list` | name, title, description, annotations, metadata | `RESOURCE_DEFINITION_INJECTION` |
| `resources/read` | text contents and metadata (blobs stay `RESOURCE_BLOB_UNINSPECTED`) | `RESOURCE_CONTENT_INJECTION` |
| `prompts/list` | name, title, description, argument descriptions, metadata | `PROMPT_DEFINITION_INJECTION` |
| `prompts/get` | description and message content blocks | `PROMPT_CONTENT_INJECTION` |

- Definition verdicts are cached by definition hash, model and threshold version (`tool_registry` for tools, `ml_definition_cache` for resources and prompts).
- The classifier is advisory. Request policy remains authoritative and the first deployment stays in `MONITOR`.
- Unavailable inference and partial inspection are passed through with explicit findings.

## Model

`meta-llama/Llama-Prompt-Guard-2-86M` at revision `a8ded8e` (mDeBERTa-base, 512-token context, binary benign/malicious, malicious = class index 1).

- Multilingual. Officially evaluated on en/fr/de/hi/it/pt/es/th. Text in other languages (Korean included) is still classified and additionally flagged `ML_UNSUPPORTED_LANGUAGE` ("unverified language").
- Version 2 narrowed its scope to explicit injection/jailbreak techniques to cut false positives on benign instructions. That suits prompt templates and documents, but quiet indirect instructions may be missed. Cover them in the held-out set.
- Gated under the Llama 4 Community License: accept the license on Hugging Face and confirm the deployment terms.
- Meta ships safetensors only, so export ONNX offline (example: `optimum-cli export onnx --model meta-llama/Llama-Prompt-Guard-2-86M --revision a8ded8e --task text-classification models/prompt-injection`).

## Thresholds

Threshold version `v2-pg2-provisional`. Each surface has its own (suspicious, injection) pair because benign prompt templates are made of instructions:

| Surface | Default | Override env |
|---|---|---|
| tool | 0.70 / 0.90 | `MAYAI_ML_TOOL_SUSPICIOUS_THRESHOLD`, `MAYAI_ML_TOOL_INJECTION_THRESHOLD` |
| resource | 0.70 / 0.90 | `MAYAI_ML_RESOURCE_*_THRESHOLD` |
| prompt | 0.85 / 0.97 | `MAYAI_ML_PROMPT_*_THRESHOLD` |

These defaults are provisional and must be replaced by per-surface held-out calibration values before enforcement. Changing calibrated values requires bumping `THRESHOLD_VERSION` so cached verdicts are recomputed.

## Offline model gate

No model is downloaded at runtime and MayAI does not train a model. A candidate is eligible only when attack recall is at least 90%, benign false-positive rate is at most 1%, and 512-token CPU latency on the deployment host is at most 250 ms at p95. Run `python evaluate_ml_model.py heldout.jsonl candidate_dir [candidate_dir ...]` (one to three candidates).

Evaluate each surface separately. The held-out set must include benign prompt templates, ordinary documents and READMEs, Korean attacks, and quiet indirect injections without jailbreak phrasing.

## Activation

1. Install `requirements-ml.txt` in the MayAI virtual environment.
2. Export the ONNX model and place it with the tokenizer files under `models/prompt-injection`.
3. Copy `model-manifest.example.json` to `models/prompt-injection/model-manifest.json`, replace every placeholder with the verified digest, and keep the model id and revision aligned with `MayAI.py`.
4. Run `python MayAI.py --selftest`, start the management API, and verify `/api/ml/status` reports `loaded: true` and the expected per-surface thresholds.
5. Operate in `MONITOR` for at least two weeks. Review false positives per surface (especially `PROMPT_*`), unverified-language counts, partial inspections, unavailable events and p95/p99 latency.
6. Enable `ENFORCE` only after the acceptance gate is met, and only through explicit response DENY policies for the `*_INJECTION` findings.

## Operational defaults

- Classification labels: `BENIGN`, `SUSPICIOUS`, `INJECTION`.
- Chunk size: 510 payload tokens plus model special tokens; maximum 16 chunks per response (long `resources/read` documents raise `ML_PARTIAL_INSPECTION`).
- Timeouts: 500 ms per chunk and 2 seconds per response.
- Audit storage contains hashes, redacted previews, paths, model metadata and latency, never full extracted text.
- Image OCR, audio transcription, blob resources and request-argument propagation analysis are out of scope.

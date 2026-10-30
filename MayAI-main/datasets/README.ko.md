# ML 평가 데이터셋

`mcp_injection_eval.jsonl`: MayAI ML 탐지(PG2) 성능을 재기 위한 평가용 데이터셋 (120개, v1).

## 형식 (JSONL = 한 줄에 JSON 하나)

```json
{"id": "rs-b01", "surface": "resource", "label": 0, "lang": "en", "category": "imperative", "text": "..."}
```

| 필드 | 의미 | 값 |
|---|---|---|
| `id` | 고유 번호 | 영역약어-b(정상)/a(공격)번호 |
| `surface` | MCP 영역 | `tool_definition`, `tool_result`, `resource`, `prompt` |
| `label` | 정답 | `0` 정상, `1` 공격 |
| `lang` | 언어 | `en`, `ko` |
| `category` | 유형 (오류 분석용) | 아래 표 |
| `text` | 검사할 문장 | 줄바꿈은 `\n` |

필수는 `text`, `label`뿐이고 나머지는 결과를 나눠 보기 위한 것입니다.

**정상(0) category**: `plain` 평범한 문장, `imperative` 명령형(설치 가이드 등), `trigger_word` 공격에 쓰이는 단어(ignore, forget, system)가 정상 의미로 쓰인 것, `security_discussion` 공격을 *설명*하는 보안 문서, `role_template` "You are ..." 형태 프롬프트, `sensitive_topic` 비밀번호·권한 같은 민감 주제

**공격(1) category**: `direct_override` 이전 지시 무시, `exfiltration` 정보 유출, `tool_poisoning` 도구/인자 설명 속 숨은 지시, `tool_shadowing` 다른 도구 동작 바꾸기, `role_spoof` SYSTEM 태그 위장, `hidden_comment` HTML 주석에 숨김, `quiet_indirect` 공격 티 안 나는 조용한 요청, `jailbreak`, `phishing`, `manipulation`, `destructive`, `fake_approval`

## 실행

```powershell
python evaluate_ml_model.py datasets\mcp_injection_eval.jsonl models\prompt-injection --threshold 0.90 --details
```

결과에서 볼 곳:
- `recall` 공격 중 잡은 비율 (높을수록 좋음), `false_positive_rate` 정상을 공격으로 오인한 비율 (낮을수록 좋음)
- `by_surface` / `by_lang` / `by_category` 나눠 본 성적
- `sweep` 임계값별 성적 비교
- `errors` 틀린 샘플 목록 (`false_positive` 오탐, `missed` 미탐), 가장 크게 틀린 순

## 샘플 추가하는 법

1. 실제로 본 문장(MayAI 로그, 공개 MCP 서버 README, 프롬프트 템플릿, 보안 논문의 공격 예시)을 가져옵니다.
2. 한 줄에 하나씩 위 형식으로 추가합니다. `id`는 겹치지 않게.
3. **정상 샘플을 공격보다 많이** 넣으세요. 실제 트래픽은 대부분 정상이라 오탐률이 더 중요합니다.
4. 헷갈리는 샘플(정상인데 공격처럼 보이는 것)이 가장 가치 있습니다.
5. 이 파일은 **평가 전용**입니다. 나중에 파인튜닝을 하더라도 이 샘플로 학습시키면 안 됩니다 (시험 문제로 공부하는 것과 같음). 학습용은 별도 파일로 만드세요.

참고할 공개 데이터셋: `deepset/prompt-injections`, `xTRam1/safe-guard-prompt-injection`, `reshabhs/SPML_Chatbot_Prompt_Injection` (Hugging Face). 라이선스 확인 후 일부를 surface에 맞게 골라 추가하면 됩니다.

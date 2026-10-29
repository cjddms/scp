# MayAI 테스트 가이드 (Windows / 로컬 단일 PC)

에이전트 → **mitmproxy(MayAI)** → 테스트 MCP 서버 구조를 PC 한 대에서 만들고,
에이전트 등록 → 요청 정책 → 응답 정책 → 탐지 시나리오까지 확인하는 절차입니다.
아래 명령은 2026-10-07에 이 폴더에서 실제로 실행해 결과를 확인했습니다 (STDIO 모드 제외).

```
[test_agent_client.py] --X-Agent-ID/Token--> [mitmdump :8080 + MayAI.py] --> [test_mcp_server.py :9100]
                                                    |
                                   nac.db  <--  [관리 API/대시보드 :8000]
```

> 참고: `README.ko.md`는 예전 파일명(`nac-proxy_v2.py`), `/api/evaluate`, `allowed_targets`,
> 정책의 `protocol` 필드를 설명하지만 현재 `MayAI.py`에는 없습니다. 이 가이드가 현재 코드 기준입니다.

---

## 0. 준비

```powershell
python --version          # 3.10 이상 (3.12 확인)
pip install fastapi uvicorn mitmproxy httpx2
```

- `httpx2`는 `--selftest`의 API 테스트(`fastapi.testclient`)에만 필요합니다.
- ML 패키지(`requirements-ml.txt`)는 선택 사항입니다 (7장).

**테스트용 DB 분리 (권장)** — 기존 `nac.db`를 건드리지 않으려면, 사용하는 **모든 터미널**에서:

```powershell
$env:NAC_DB_PATH = "$env:TEMP\nac-test.db"
```

API 서버와 mitmdump가 같은 DB를 봐야 정책이 즉시 적용되므로, 세 터미널 모두 같은 값이어야 합니다.

## 1. 셀프 테스트

```powershell
python MayAI.py --selftest
# -> nac-proxy selftest: OK (all assertions passed)
```

셀프 테스트는 항상 `%TEMP%\nac-selftest.db`를 써서 실제 DB를 건드리지 않습니다.
`starlette.testclient ... requires the httpx2 package` 오류가 나면 `pip install httpx2`.

## 2. 테스트 환경 띄우기 (터미널 3개)

| 터미널 | 명령 | 역할 |
|---|---|---|
| A | `python test_mcp_server.py` | 테스트 MCP 서버 `127.0.0.1:9100` |
| B | `python MayAI.py` | 관리 API + 대시보드 `http://127.0.0.1:8000/` |
| C | `mitmdump -s MayAI.py -p 8080` | 실제 트래픽 검사 프록시 |

- Swagger UI: http://127.0.0.1:8000/docs — 아래의 API 호출은 전부 여기서도 할 수 있습니다.
- 대시보드에서도 에이전트/정책 등록, 로그·이벤트 조회가 가능합니다.

`test_mcp_server.py`의 도구:

| 도구 | 동작 | 확인 대상 |
|---|---|---|
| `echo` | 인자 그대로 반환 | 정상 흐름 |
| `get_secret` | `password=…, api_key=…` 반환 | `RESPONSE_SENSITIVE_DATA` |
| `weather` | `city=bad`면 outputSchema 위반 | `OUTPUT_SCHEMA_VIOLATION` |
| `bad_id` | 다른 JSON-RPC id로 응답 | `JSONRPC_ID_MISMATCH` |
| `delete_file` | 위험해 보이는 이름 | DENY 정책 연습 |
| (`--rugpull`로 재시작) | `echo` 설명이 바뀜 | `TOOL_DEFINITION_CHANGED` |

`test_agent_client.py`는 가짜 에이전트입니다. 기본값: `--agent agent-001 --token secret
--target 127.0.0.1:9100 --proxy 127.0.0.1:8080`. 인자는 `-a key=value`로 넘깁니다.

## 3. 요청 정책 테스트 (기본 차단)

4번째 터미널(D)에서 진행합니다.

### 3-1. 미등록 에이전트 → 차단

```powershell
python test_agent_client.py tools/list
# HTTP 403  "reason": "unregistered agent: agent-001"
```

### 3-2. 에이전트 등록

로컬 테스트에서는 mitmproxy가 보는 출발지 IP가 `127.0.0.1`이므로 `source_ip`도 그 값입니다.

```powershell
$api = "http://127.0.0.1:8000"
$body = @{ agent_id="agent-001"; agent_name="Local Test Agent"; token="secret"; source_ip="127.0.0.1" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/agents" -ContentType application/json -Body $body
```

```powershell
python test_agent_client.py tools/list
# HTTP 403  "reason": "no matching policy (default deny)"   <- 인증 통과, 정책 없음
python test_agent_client.py tools/list --token wrong
# HTTP 403  "reason": "invalid token"
```

### 3-3. 정책 추가 (ALLOW 전체 + 특정 도구 DENY)

정책 필드: `agent_id`, `target`(`host:port` 또는 `stdio:<이름>`), `tool`, `action`, `priority`.
`*`는 와일드카드입니다. **판단 순서: DENY 우선 → 더 구체적인 정책 → priority 숫자 작은 것.**
MCP `tools/call`이면 `tool` = 도구 이름, 그 외 요청은 `tool` = JSON-RPC method (`tools/list`, `initialize` …).

```powershell
$p1 = @{ name="allow-mcp-all"; agent_id="agent-001"; target="127.0.0.1:9100"; tool="*"; action="ALLOW"; priority=100 } | ConvertTo-Json
$p2 = @{ name="deny-delete";   agent_id="agent-001"; target="127.0.0.1:9100"; tool="delete_file"; action="DENY"; priority=10 } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/policies" -ContentType application/json -Body $p1
Invoke-RestMethod -Method Post "$api/api/policies" -ContentType application/json -Body $p2
```

### 3-4. 결과 확인

| 명령 | 기대 결과 |
|---|---|
| `python test_agent_client.py tools/list` | HTTP 200, 도구 목록 |
| `python test_agent_client.py tools/call echo -a text=hello` | HTTP 200, `"hello"` |
| `python test_agent_client.py tools/call delete_file -a path=/etc/passwd` | HTTP 403, `matched policy 'deny-delete'` |
| `python test_agent_client.py tools/list --target 127.0.0.1:9101` | HTTP 403, default deny (포트가 다르면 다른 대상) |
| `python test_agent_client.py tools/list --agent ghost` | HTTP 403, unregistered agent |
| `python test_agent_client.py tools/call echo -a "text=my password is 1234"` | HTTP 200 (허용) + 로그에 `SENSITIVE_DATA_EXPOSURE`, 위험도 상승 |

> 요청 쪽 민감정보·권한 남용은 **위험도/이벤트**만 남기고 차단하지 않습니다. 차단은 정책만 결정합니다.

로그 확인 (PowerShell 5.1에서는 `Invoke-RestMethod`를 **괄호로 감싸야** 배열이 행 단위로 나옵니다):

```powershell
(Invoke-RestMethod "$api/api/logs?limit=10") | Format-Table log_id,agent_id,source,destination,tool,decision,reason
```

**관리자 결정 → 정책 자동 생성**: 차단된 로그를 허용하고 싶으면

```powershell
Invoke-RestMethod -Method Post "$api/api/decisions/<log_id>" -ContentType application/json -Body '{"decision":"ALLOW","reason":"reviewed"}'
```

해당 agent/target/tool로 priority 10 정책이 생성됩니다.

## 4. 응답 정책 테스트 (MONITOR → ENFORCE)

응답 정책은 요청 정책과 별개이며 **기본 허용**, 초기 모드는 **MONITOR**(기록만)입니다.

```powershell
# (1) 정책 없음: 탐지만 기록
python test_agent_client.py tools/call get_secret          # HTTP 200

# (2) 민감정보 응답 DENY 정책 추가 - MONITOR라 아직 통과, policy_action=DENY로 기록
$rp = @{ name="deny-resp-sensitive"; finding="RESPONSE_SENSITIVE_DATA"; action="DENY"; priority=10 } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/response-policies" -ContentType application/json -Body $rp
python test_agent_client.py tools/call get_secret          # HTTP 200

# (3) ENFORCE 전환 → 실제 차단
Invoke-RestMethod -Method Put "$api/api/settings/response-enforcement" -ContentType application/json -Body '{"mode":"ENFORCE"}'
python test_agent_client.py tools/call get_secret
# HTTP 403  {"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"AI-NAC response blocked by policy", ...}}
```

결과 비교:

```powershell
(Invoke-RestMethod "$api/api/responses") | Select-Object response_id,tool,@{n='findings';e={$_.findings -join ','}},policy_action,effective_action,enforcement_mode | Format-Table -AutoSize
```

실측 예시:

```
response_id tool       findings                 policy_action effective_action enforcement_mode
          6 get_secret RESPONSE_SENSITIVE_DATA  DENY          DENY             ENFORCE   <- 차단
          5 get_secret RESPONSE_SENSITIVE_DATA  DENY          ALLOW            MONITOR   <- 기록만
          4 get_secret RESPONSE_SENSITIVE_DATA  ALLOW         ALLOW            MONITOR
```

`finding`에 쓸 수 있는 값: `RESPONSE_SENSITIVE_DATA`, `JSONRPC_ID_MISMATCH`, `INVALID_JSON_RESPONSE`,
`UNEXPECTED_CONTENT_TYPE`, `RESPONSE_STREAMING_SKIPPED`, `RESPONSE_TOO_LARGE_SKIPPED`,
`TOOL_DEFINITION_CHANGED`, `RESOURCE_DEFINITION_CHANGED`, `PROMPT_DEFINITION_CHANGED`, `PROMPT_CONTENT_CHANGED`,
`OUTPUT_SCHEMA_VIOLATION`, `RESOURCE_BLOB_UNINSPECTED`, `TOOL_DEFINITION_INJECTION`, `TOOL_RESULT_INJECTION`,
`RESOURCE_DEFINITION_INJECTION`, `RESOURCE_CONTENT_INJECTION`, `PROMPT_DEFINITION_INJECTION`, `PROMPT_CONTENT_INJECTION`,
`ML_SUSPICIOUS_CONTENT`, `ML_PARTIAL_INSPECTION`, `ML_UNSUPPORTED_LANGUAGE`, `ML_INSPECTION_UNAVAILABLE`, `*`.

응답 정책은 finding마다 따로 판정합니다 (더 구체적 → priority 작은 것 → 동률이면 DENY).
특정 도구만 예외를 두려면 `tool="get_secret"; action="ALLOW"` 같은 더 구체적인 정책을 추가하세요.

## 5. 탐지 시나리오

| 시나리오 | 명령 | 기대 finding / 이벤트 |
|---|---|---|
| JSON-RPC id 위조 | `python test_agent_client.py tools/call bad_id` | `JSONRPC_ID_MISMATCH` (high) |
| outputSchema 위반 | `python test_agent_client.py tools/call weather -a city=bad` | `OUTPUT_SCHEMA_VIOLATION` |
| inputSchema 위반 | 먼저 `tools/list` 1회 후 `python test_agent_client.py tools/call weather` (city 누락) | 요청 쪽 `INPUT_SCHEMA_VIOLATION` |
| Rug-pull | `tools/list` 1회 → 터미널 A를 `python test_mcp_server.py --rugpull`로 재시작 → `tools/list` 다시 | `TOOL_DEFINITION_CHANGED` (high) |

이벤트 확인:

```powershell
(Invoke-RestMethod "$api/api/events") | Select-Object -First 10 | Format-Table event_id,event_type,severity,target,reason
```

트래픽 탐색 (전송/방향/규칙 필터):

```powershell
(Invoke-RestMethod "$api/api/explore?direction=response&rule=TOOL_DEFINITION_CHANGED").rows
```

## 6. 실제 MCP 클라이언트로 테스트

### 6-1. HTTP MCP 서버 (mitmproxy 경유)

에이전트 **프로세스에만** 프록시를 지정하고, 모든 요청에 `X-Agent-ID` / `X-Agent-Token` 헤더를 넣어야 합니다.

```powershell
$env:HTTP_PROXY  = "http://127.0.0.1:8080"
$env:HTTPS_PROXY = "http://127.0.0.1:8080"
# 이 터미널에서 에이전트 실행
```

- **localhost 우회 주의**: 많은 HTTP 라이브러리가 `localhost`/`127.0.0.1` 대상이면 프록시를 건너뜁니다.
  로그에 아무것도 안 쌓이면 서버를 다른 IP로 띄우거나 `NO_PROXY`를 확인하세요.
- **HTTPS 대상**: 에이전트가 mitmproxy CA를 신뢰해야 합니다. mitmdump 실행 중 프록시를 거쳐
  http://mitm.it 에서 인증서를 받아 설치합니다 (테스트 PC에서만).
- **SSE 응답**(`text/event-stream`)은 검사하지 않고 `RESPONSE_STREAMING_SKIPPED`로 기록됩니다.
- **다른 PC의 에이전트**(예: VM `192.168.56.102`): mitmdump는 `0.0.0.0:8080`으로 열리므로 방화벽에서
  8080을 허용하고, 에이전트 `source_ip`를 그 VM의 IP로 등록합니다. 정책 `target`은 프록시가 본
  실제 MCP 서버 `host:port`(예: `192.168.56.104:9000`)입니다.

### 6-2. STDIO 테스트 (가짜 클라이언트로, 검증됨)

`--stdio <서버이름>`을 붙이면 `test_agent_client.py`가 MCP stdio 클라이언트처럼
`MayAI.py stdio --server-name <서버이름> -- python test_mcp_server.py --stdio`를 띄우고 요청 1건을 보냅니다.
mitmdump·HTTP 테스트 서버는 필요 없고, 결과는 같은 `nac.db`에 `transport=stdio`로 기록됩니다.

- 에이전트: STDIO 출발지는 항상 `127.0.0.1`이라 `agent-001`을 그대로 쓸 수 있습니다.
- 정책 target: `stdio:test-server`
- 실행 예: `python test_agent_client.py tools/call echo -a text=hi --stdio test-server`
  (Rug-pull은 `--rugpull` 추가)

### 6-3. STDIO MCP 서버 (Claude Desktop 등 실제 클라이언트) — 직접 실행해 보지는 않음

MCP 클라이언트가 서버 대신 `MayAI.py stdio`를 실행하게 합니다 (`mcp.json` 예시 참고).

1. 에이전트 등록: `agent_id="agent-stdio"`, `token="s3cret"`, **`source_ip="127.0.0.1"`** (STDIO는 항상 127.0.0.1)
2. 정책 등록: `target="stdio:everything"` (`--server-name` 값), `tool="*"`, `ALLOW`
3. 클라이언트 설정에 `mcp.json`의 `mayai-everything` 항목 추가. `args`의 `MayAI.py`는 **절대 경로**로,
   DB를 분리했다면 `env`에 `NAC_DB_PATH`도 추가합니다.
4. 클라이언트에서 도구 사용 → `/api/logs`에서 `transport=stdio` 기록 확인

## 7. ML 프롬프트 인젝션 탐지 (tools / resources / prompts)

모델: `meta-llama/Llama-Prompt-Guard-2-86M` (ONNX). 설치는 `tool-poisoning-ml-plan.md` 참고.
대시보드 **Responses** 탭 상단 카드에서 `ML 분류기: 로드됨`인지 먼저 확인합니다
(첫 MCP 응답이 지나간 뒤 로드됩니다).

### 7-1. 내용(content) 인젝션 — 터미널 A는 평소대로 `python test_mcp_server.py`

| 명령 | 기대 finding |
|---|---|
| `python test_agent_client.py tools/call fetch_page -a page=safe` | 없음 |
| `python test_agent_client.py tools/call fetch_page -a page=evil` | `TOOL_RESULT_INJECTION` |
| `python test_agent_client.py tools/call fetch_page -a page=evil_ko` | `TOOL_RESULT_INJECTION`, `ML_UNSUPPORTED_LANGUAGE` |
| `python test_agent_client.py tools/call fetch_page -a page=quiet` | **없음** — 조용한 간접 지시는 PG2가 놓침 (알려진 한계) |
| `python test_agent_client.py resources/read file:///docs/readme.md` | 없음 (명령형 README, 오탐 확인용) |
| `python test_agent_client.py resources/read file:///docs/notes.md` | `RESOURCE_CONTENT_INJECTION` |
| `python test_agent_client.py resources/read file:///docs/notes_ko.md` | `RESOURCE_CONTENT_INJECTION`, `ML_UNSUPPORTED_LANGUAGE` |
| `python test_agent_client.py resources/read file:///docs/logo.png` | `RESOURCE_BLOB_UNINSPECTED` |
| `python test_agent_client.py prompts/get code_review -a "diff=+ print(1)"` | 없음 (지시문 템플릿, 오탐 확인용) |
| `python test_agent_client.py prompts/get summarize -a topic=revenue` | `PROMPT_CONTENT_INJECTION` |

### 7-2. 정의(definition) 포이즈닝 — 터미널 A를 `python test_mcp_server.py --poison`으로 재시작

| 명령 | 기대 finding |
|---|---|
| `python test_agent_client.py tools/list` | `TOOL_DEFINITION_INJECTION` (+ 정의가 바뀌었으면 `TOOL_DEFINITION_CHANGED`) |
| `python test_agent_client.py resources/list` | `RESOURCE_DEFINITION_INJECTION` |
| `python test_agent_client.py prompts/list` | `PROMPT_DEFINITION_INJECTION` |

`resources/list`는 한국어 리소스(`회의록`)가 있어 `ML_UNSUPPORTED_LANGUAGE`가 함께 붙습니다.

### 7-3. 차단까지 확인

Resp Policies 탭에서 finding=`RESOURCE_CONTENT_INJECTION`, action=`DENY` 정책 추가 →
Enforcement를 `ENFORCE`로 바꾸고 `notes.md`를 다시 읽으면 HTTP 403 (`AI-NAC response blocked by policy`).

### ML 끄기

ML을 테스트하지 않을 때 (API가 없어 DB 직접 수정):

```powershell
python -c "import os,sqlite3;c=sqlite3.connect(os.environ.get('NAC_DB_PATH','nac.db'));c.execute(\"UPDATE settings SET value='0' WHERE setting_key='ml_enabled'\");c.commit()"
```

## 8. 정리 / 초기화

```powershell
# 테스트 데이터만 지우기
Invoke-RestMethod -Method Delete "$api/api/logs"
Invoke-RestMethod -Method Delete "$api/api/policies"
Invoke-RestMethod -Method Delete "$api/api/response-policies"
Invoke-RestMethod -Method Delete "$api/api/agents"

# 또는 테스트 DB 통째로 삭제 (서버 종료 후)
Remove-Item "$env:TEMP\nac-test.db"
```

## 체크리스트

- [ ] selftest OK
- [ ] 미등록 / 토큰 오류 / 정책 없음 → 403
- [ ] ALLOW 정책 → 200, 특정 도구 DENY → 403 (DENY 우선)
- [ ] 같은 IP 다른 포트 → 별도 대상으로 차단
- [ ] 요청 민감정보 → 허용되지만 위험도·이벤트 기록
- [ ] 응답 DENY 정책: MONITOR는 기록만, ENFORCE는 JSON-RPC 403
- [ ] id 위조 / outputSchema / inputSchema / rug-pull 탐지
- [ ] `X-Agent-*` 헤더가 MCP 서버로 전달되지 않음 (코드상 제거됨 — 확인하려면 `test_mcp_server.py`의 `do_POST`에서 `print(self.headers)`)

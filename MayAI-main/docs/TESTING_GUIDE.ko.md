# MayAI 테스트 가이드 (Windows / 로컬 단일 PC)

에이전트 → **mitmproxy(MayAI)** → 테스트 MCP 서버 구조를 PC 한 대에서 만들고,
에이전트 등록 → 요청 정책 → 응답 정책 → 탐지 시나리오까지 확인하는 절차입니다.
아래 명령은 2026-10-07에 이 폴더에서 실제로 실행해 결과를 확인했습니다 (STDIO 모드 제외).

```
[tests/test_agent_client.py] --X-Agent-ID/Token--> [mitmdump :8080 + MayAI.py] --> [test_mcp_server.py :9100]
                                                    |
                                   nac.db  <--  [관리 API/대시보드 :8000]
```

> 참고: `README.ko.md`는 예전 파일명(`nac-proxy_v2.py`), `/api/evaluate`, `allowed_targets`,
> 정책의 `protocol` 필드를 설명하지만 현재 `MayAI.py`에는 없습니다. 이 가이드가 현재 코드 기준입니다.

---


> 모든 명령은 `MayAI-main` 폴더에서 실행합니다 (예: `python tests/test_agent_client.py ...`).
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
$env:MAYAI_ADMIN_KEY = "test-admin-key"   # 관리자 키 (아래 설명)
```

API 서버와 mitmdump가 같은 DB를 봐야 정책이 즉시 적용되므로, 세 터미널 모두 같은 값이어야 합니다.

**관리자 키** — 관리 API의 변경 요청(POST·PUT·PATCH·DELETE)은 전부 `X-Admin-Key` 헤더가 필요합니다(없거나 틀리면 401).
조회(GET)는 키 없이 됩니다. STDIO 에이전트가 같은 PC에서 돌기 때문에, 키가 없으면 감염된 에이전트가
스스로 정책을 바꾸거나 자기 격리를 해제할 수 있어서입니다.
- `MAYAI_ADMIN_KEY`를 지정하고 서버를 띄우면 그 값이 키입니다.
- 지정하지 않으면 처음 실행할 때 키를 만들어 **콘솔에 한 번만** 출력합니다(DB에는 해시만 저장).
- 대시보드는 변경 작업 때 키를 물어보고 이 브라우저에만 저장합니다. 상단 **관리자 키** 버튼으로 바꿀 수 있습니다.
- 성공한 변경 요청은 모두 감사 로그(`에이전트 신뢰` 탭)에 남고 정책 버전이 1씩 올라갑니다.

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
| A | `python tests/test_mcp_server.py` | 테스트 MCP 서버 `127.0.0.1:9100` |
| B | `python MayAI.py` | 관리 API + 대시보드 `http://127.0.0.1:8000/` |
| C | `mitmdump -s MayAI.py -p 8080` | 실제 트래픽 검사 프록시 |

- Swagger UI: http://127.0.0.1:8000/docs — 아래의 API 호출은 전부 여기서도 할 수 있습니다.
- 대시보드에서도 에이전트/정책 등록, 로그·이벤트 조회가 가능합니다.

`tests/test_mcp_server.py`의 도구:

| 도구 | 동작 | 확인 대상 |
|---|---|---|
| `echo` | 인자 그대로 반환 | 정상 흐름 |
| `get_secret` | `password=…, api_key=…` 반환 | `RESPONSE_SENSITIVE_DATA` |
| `weather` | `city=bad`면 outputSchema 위반 | `OUTPUT_SCHEMA_VIOLATION` |
| `bad_id` | 다른 JSON-RPC id로 응답 | `JSONRPC_ID_MISMATCH` |
| `delete_file` | 위험해 보이는 이름 | DENY 정책 연습 |
| (`--rugpull`로 재시작) | `echo` 설명이 바뀜 | `TOOL_DEFINITION_CHANGED` |

`tests/test_agent_client.py`는 가짜 에이전트입니다. 기본값: `--agent agent-001 --token secret
--target 127.0.0.1:9100 --proxy 127.0.0.1:8080`. 인자는 `-a key=value`로 넘깁니다.

## 3. 요청 정책 테스트 (기본 차단)

4번째 터미널(D)에서 진행합니다.

### 3-1. 미등록 에이전트 → 차단

```powershell
python tests/test_agent_client.py tools/list
# HTTP 403  "reason": "unregistered agent: agent-001"
```

### 3-2. 에이전트 등록

로컬 테스트에서는 mitmproxy가 보는 출발지 IP가 `127.0.0.1`이므로 `source_ip`도 그 값입니다.

```powershell
$api = "http://127.0.0.1:8000"
$h = @{ "X-Admin-Key" = $env:MAYAI_ADMIN_KEY }   # 변경 요청에 붙이는 관리자 키
$body = @{ agent_id="agent-001"; agent_name="Local Test Agent"; token="secret"; source_ip="127.0.0.1" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/agents" -ContentType application/json -Body $body -Headers $h
```

```powershell
python tests/test_agent_client.py tools/list
# HTTP 403  "reason": "no matching policy (default deny)"   <- 인증 통과, 정책 없음
python tests/test_agent_client.py tools/list --token wrong
# HTTP 403  "reason": "invalid token"
```

### 3-3. 정책 추가 (ALLOW 전체 + 특정 도구 DENY)

정책 필드: `agent_id`, `target`(`host:port` 또는 `stdio:<이름>`), `tool`, `action`.
`*`는 와일드카드입니다. **판단 순서: DENY 먼저 → 더 구체적인 정책.**
MCP `tools/call`이면 `tool` = 도구 이름, 그 외 요청은 `tool` = JSON-RPC method (`tools/list`, `initialize` …).

```powershell
$p1 = @{ name="allow-mcp-all"; agent_id="agent-001"; target="127.0.0.1:9100"; tool="*"; action="ALLOW" } | ConvertTo-Json
$p2 = @{ name="deny-delete";   agent_id="agent-001"; target="127.0.0.1:9100"; tool="delete_file"; action="DENY" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/policies" -ContentType application/json -Body $p1 -Headers $h
Invoke-RestMethod -Method Post "$api/api/policies" -ContentType application/json -Body $p2 -Headers $h
```

### 3-4. 결과 확인

| 명령 | 기대 결과 |
|---|---|
| `python tests/test_agent_client.py tools/list` | HTTP 200, 도구 목록 |
| `python tests/test_agent_client.py tools/call echo -a text=hello` | HTTP 200, `"hello"` |
| `python tests/test_agent_client.py tools/call delete_file -a path=/etc/passwd` | HTTP 403, `matched policy 'deny-delete'` |
| `python tests/test_agent_client.py tools/list --target 127.0.0.1:9101` | HTTP 403, default deny (포트가 다르면 다른 대상) |
| `python tests/test_agent_client.py tools/list --agent ghost` | HTTP 403, unregistered agent |
| `python tests/test_agent_client.py tools/call echo -a "text=my password is 1234"` | HTTP 200 (허용) + 로그에 `SENSITIVE_DATA_EXPOSURE`, 위험도 상승 |

> 요청 쪽 민감정보·권한 남용은 **위험도/이벤트**만 남기고 차단하지 않습니다. 차단은 정책만 결정합니다.

로그 확인 (PowerShell 5.1에서는 `Invoke-RestMethod`를 **괄호로 감싸야** 배열이 행 단위로 나옵니다):

```powershell
(Invoke-RestMethod "$api/api/logs?limit=10") | Format-Table log_id,agent_id,source,destination,tool,decision,reason
```

**관리자 결정 → 정책 자동 생성**: 차단된 로그를 허용하고 싶으면

```powershell
Invoke-RestMethod -Method Post "$api/api/decisions/<log_id>" -ContentType application/json -Body '{"decision":"ALLOW","reason":"reviewed"}' -Headers $h
```

해당 agent/target/tool로 정책이 생성됩니다.

## 4. 응답 정책 테스트 (MONITOR → ENFORCE)

응답 정책은 요청 정책과 별개이며 **기본 허용**, 초기 모드는 **MONITOR**(기록만)입니다.

```powershell
# (1) 정책 없음: 탐지만 기록
python tests/test_agent_client.py tools/call get_secret          # HTTP 200

# (2) 민감정보 응답 DENY 정책 추가 - MONITOR라 아직 통과, policy_action=DENY로 기록
$rp = @{ name="deny-resp-sensitive"; finding="RESPONSE_SENSITIVE_DATA"; action="DENY" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$api/api/response-policies" -ContentType application/json -Body $rp -Headers $h
python tests/test_agent_client.py tools/call get_secret          # HTTP 200

# (3) ENFORCE 전환 → 실제 차단
Invoke-RestMethod -Method Put "$api/api/settings/response-enforcement" -ContentType application/json -Body '{"mode":"ENFORCE"}' -Headers $h
python tests/test_agent_client.py tools/call get_secret
# HTTP 403  {"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"MayAI response blocked by policy", ...}}
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

응답 정책은 finding마다 따로 판정합니다 (더 구체적인 정책 → 동률이면 DENY).
특정 도구만 예외를 두려면 `tool="get_secret"; action="ALLOW"` 같은 더 구체적인 정책을 추가하세요.

## 5. 탐지 시나리오

| 시나리오 | 명령 | 기대 finding / 이벤트 |
|---|---|---|
| JSON-RPC id 위조 | `python tests/test_agent_client.py tools/call bad_id` | `JSONRPC_ID_MISMATCH` (high) |
| outputSchema 위반 | `python tests/test_agent_client.py tools/call weather -a city=bad` | `OUTPUT_SCHEMA_VIOLATION` |
| inputSchema 위반 | 먼저 `tools/list` 1회 후 `python tests/test_agent_client.py tools/call weather` (city 누락) | 요청 쪽 `INPUT_SCHEMA_VIOLATION` |
| Rug-pull | `tools/list` 1회 → 터미널 A를 `python tests/test_mcp_server.py --rugpull`로 재시작 → `tools/list` 다시 | `TOOL_DEFINITION_CHANGED` (high) |

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

`--stdio <서버이름>`을 붙이면 `tests/test_agent_client.py`가 MCP stdio 클라이언트처럼
`MayAI.py stdio --server-name <서버이름> -- python tests/test_mcp_server.py --stdio`를 띄우고 요청 1건을 보냅니다.
mitmdump·HTTP 테스트 서버는 필요 없고, 결과는 같은 `nac.db`에 `transport=stdio`로 기록됩니다.

- 에이전트: STDIO 출발지는 항상 `127.0.0.1`이라 `agent-001`을 그대로 쓸 수 있습니다.
- 정책 target: `stdio:test-server`
- **MAC 라벨 필요**: STDIO는 MAC(제로 트러스트)이 적용돼, 라벨이 없는 도구·리소스·프롬프트는 L4로 간주되어
  `MAC_READ_UP_DENY`로 차단됩니다. 대시보드 **MAC 보안 등급** 탭에서 `stdio:test-server`, 객체 `*`,
  등급 L2, 흐름 `읽기` 라벨을 하나 추가하세요 (`initialize`, `tools/list` 같은 조회는 라벨 없이도 통과).
- 실행 예: `python tests/test_agent_client.py tools/call echo -a text=hi --stdio test-server`
  (Rug-pull은 `--rugpull` 추가)

### 6-3. STDIO MCP 서버 (Claude Desktop 등 실제 클라이언트) — 직접 실행해 보지는 않음

MCP 클라이언트가 서버 대신 `MayAI.py stdio`를 실행하게 합니다 (`examples/mcp.json` 예시 참고).

1. 에이전트 등록: `agent_id="agent-stdio"`, `token="s3cret"`, **`source_ip="127.0.0.1"`** (STDIO는 항상 127.0.0.1)
2. 정책 등록: `target="stdio:everything"` (`--server-name` 값), `tool="*"`, `ALLOW`
   + MAC 라벨 등록: `stdio:everything`의 도구들에 등급·흐름 지정 (없으면 L4로 간주되어 차단)
3. 클라이언트 설정에 `examples/mcp.json`의 `mayai-everything` 항목 추가. `args`의 `MayAI.py`는 **절대 경로**로,
   DB를 분리했다면 `env`에 `NAC_DB_PATH`도 추가합니다.
4. 클라이언트에서 도구 사용 → `/api/logs`에서 `transport=stdio` 기록 확인

### 6-4. MAC 제로 트러스트 (STDIO 전용)

STDIO 요청은 요청 정책을 통과한 뒤 MAC 검사를 한 번 더 받습니다. 둘 다 통과해야 MCP 서버로 전달됩니다.

| 등급 | 분류 | 데이터 예시 |
|---|---|---|
| L4 | Critical (핵심기밀) | 암호화 키, 핵심 보안 정책, 최고관리자 인증정보 |
| L3 | Restricted (제한정보) | 개인정보, 내부 보안 로그, 중요 시스템 설정 |
| L2 | Internal (내부정보) | 업무 문서, 내부 운영 자료 |
| L1 | Public (공개정보) | 공개 문서, 대외 홍보 자료 |

- **에이전트 허가 등급**: 에이전트 탭에서 지정 (기본 L2)
- **대상 라벨**: MAC 보안 등급 탭에서 `stdio:서버이름` + 도구/리소스 URI/프롬프트 이름(`*` 와일드카드)에
  등급과 데이터 흐름(읽기 / 쓰기 / 외부 전송) 지정. 라벨이 없으면 L4로 간주합니다.
- **규칙**: ① 허가 등급보다 높은 대상 접근 금지(`MAC_READ_UP_DENY`)
  ② 세션이 받은 데이터보다 낮은 등급 대상으로 쓰기·외부 전송 금지(`MAC_WRITE_DOWN_DENY`)
- **세션**: 에이전트 실행 1회 = 세션 1개 (같은 실행에서 띄운 STDIO 서버들은 세션 공유).
  세션 등급은 받은 데이터 등급만큼 올라가고(응답에 민감정보가 있으면 최소 L3), **새 세션(재시작·재인증)은
  직전 세션 등급을 이어받습니다** — 재시작으로 받은 데이터 이력을 지울 수 없게 하기 위해서입니다.
  관리자가 대시보드에서 **L1로 초기화**할 때만 내려갑니다.
- `tools/call`, `resources/read`, `prompts/get`만 검사합니다. `initialize`, `*/list`, 알림은 요청 정책만 적용.
- HTTP(mitmproxy) 경로에는 적용되지 않습니다.

### 6-5. 에이전트 신뢰 상태 (STDIO 제로 트러스트)

세션과 별도로 **에이전트마다 영구 신뢰 상태**를 둡니다. 세션은 초기화·만료돼도 이 상태는 재시작·재인증·
에이전트 삭제 후 재등록으로 바뀌지 않습니다(**재인증 성공 ≠ 신뢰 회복**). 대시보드 **에이전트 신뢰** 탭.

| 상태 | 의미 | STDIO 요청 |
|---|---|---|
| NORMAL (정상) | 기본 | MAC 범위 안에서 허용 |
| SUSPICIOUS (의심) | 고위험 신호 발생 | **읽기만**, 허용 등급(기본 L2) 이하만 — `TRUST_RESTRICTED_DENY` |
| COMPROMISED (침해) | 반복 위반·유출 시도 | **전부 차단**, 세션 전부 폐기, 현재 토큰 폐기 — `TRUST_QUARANTINED` |
| RECOVERY (복구 중) | 원인 제거 후 복구 요청됨 | `initialize`·목록은 허용, 데이터 접근(`tools/call` 등)은 차단 |
| NORMAL + 관찰 중 | 복구 승인 직후 | 의심과 같은 제한, **위반 1번이면 바로 침해** |

판단 순서(한 곳에서): 신뢰 게이트 → 요청 정책 → MAC → 신뢰 기반 권한 축소. 신뢰 상태는 MAC 권한을 **좁히기만** 하고 넓히지 않습니다.

**자동 전환** (탭에서 수정 가능, 임시 운영값):
- 위반 = 에이전트 스스로의 고위험 요청: `MAC_READ_UP_DENY`(라벨 있는 대상만), `MAC_WRITE_DOWN_DENY`, `REQUEST_SENSITIVE_PATH`, `REQUEST_DANGEROUS_COMMAND`
- 유출 시도 = `MAC_WRITE_DOWN_DENY` / 노출 = 에이전트가 받은 인젝션 응답(의심까지만 반영)
- 위반+노출 1회 → 의심, 위반 3회 또는 유출 시도 2회 → 침해. 횟수는 마지막 검증(복구 승인·검증 완료) 이후부터.
- 격리되는 순간 처리 중이던 요청의 **응답도 에이전트에게 전달하지 않습니다**.

**복구 절차** (탭의 버튼, 모두 관리자 키 + 승인자 이름 필요, 감사 로그 기록):
1. 침해 → **복구 요청**: 원인 제거 확인 + 조치 내용 기록 → RECOVERY
2. **에이전트 탭에서 토큰 재설정** (안 하면 승인 거부 409)
3. **복구 승인**: 실행 환경 무결성은 자동 검증 불가(`검증 불가`)임을 승인자가 인정 → 정상 + 관찰 중
4. 이상 없으면 **관찰 종료** → 정상(제한 해제). 의심 상태는 **검증 완료**로 정상 복귀.
5. 복구 후에는 에이전트를 **다시 실행**해야 합니다(폐기된 세션은 되살아나지 않음).

신뢰 저장소(DB)를 읽지 못하면 STDIO 요청과 응답은 모두 차단됩니다(Fail-Closed). HTTP(mitmproxy) 경로에는 신뢰 상태가 적용되지 않습니다.

**데모** (관리 API 실행 중, 같은 `NAC_DB_PATH`·`MAYAI_ADMIN_KEY`):

```powershell
python tests/test_mac_demo.py      # 실행할 때마다 새 데모 에이전트(demo-시분초, 허가 L2) 등록 후 시나리오 실행
```

| # | 호출 | 기대 결과 |
|---|---|---|
| 1 | `stdio:chat` `echo` (L1 외부 전송) | 허용 — 새 세션 L1 |
| 2 | `stdio:docs` `fetch_page` (L2 읽기) | 허용 — 세션 L2 |
| 3 | `stdio:docs` `delete_file` (L2 쓰기) | 허용 — 같은 등급 |
| 4 | `stdio:chat` `echo` | 차단 `MAC_WRITE_DOWN_DENY` → **의심** 전환 |
| 5 | `stdio:docs` `delete_file` | 차단 `TRUST_RESTRICTED_DENY` — MAC은 허용이지만 의심이라 쓰기 금지 |
| 6 | `stdio:docs` `fetch_page` | 허용 — L2 이하 읽기는 가능 |
| 7 | `stdio:hr-db` `get_secret` (L3) | 차단 `MAC_READ_UP_DENY` — 위반 2 |
| 8 | `stdio:chat` `echo` | 차단 — 유출 시도 2회 → **침해**, 세션·토큰 폐기 |
| 9 | `stdio:docs` `fetch_page` | 차단 `TRUST_QUARANTINED` |
| 10 | 새 프로세스로 재실행(재인증) | 차단 — "re-authentication does not restore trust" |

그 뒤 대시보드에서 복구 요청 → 토큰 재설정 → 복구 승인 순서로 되돌려 볼 수 있습니다.

## 7. ML 프롬프트 인젝션 탐지 (tools / resources / prompts)

모델: `meta-llama/Llama-Prompt-Guard-2-86M` (ONNX). 설치는 `docs/tool-poisoning-ml-plan.md` 참고.
대시보드 **Responses** 탭 상단 카드에서 `ML 분류기: 로드됨`인지 먼저 확인합니다
(첫 MCP 응답이 지나간 뒤 로드됩니다).

### 7-1. 내용(content) 인젝션 — 터미널 A는 평소대로 `python tests/test_mcp_server.py`

| 명령 | 기대 finding |
|---|---|
| `python tests/test_agent_client.py tools/call fetch_page -a page=safe` | 없음 |
| `python tests/test_agent_client.py tools/call fetch_page -a page=evil` | `TOOL_RESULT_INJECTION` |
| `python tests/test_agent_client.py tools/call fetch_page -a page=evil_ko` | `TOOL_RESULT_INJECTION`, `ML_UNSUPPORTED_LANGUAGE` |
| `python tests/test_agent_client.py tools/call fetch_page -a page=quiet` | **없음** — 조용한 간접 지시는 PG2가 놓침 (알려진 한계) |
| `python tests/test_agent_client.py resources/read file:///docs/readme.md` | 없음 (명령형 README, 오탐 확인용) |
| `python tests/test_agent_client.py resources/read file:///docs/notes.md` | `RESOURCE_CONTENT_INJECTION` |
| `python tests/test_agent_client.py resources/read file:///docs/notes_ko.md` | `RESOURCE_CONTENT_INJECTION`, `ML_UNSUPPORTED_LANGUAGE` |
| `python tests/test_agent_client.py resources/read file:///docs/logo.png` | `RESOURCE_BLOB_UNINSPECTED` |
| `python tests/test_agent_client.py prompts/get code_review -a "diff=+ print(1)"` | 없음 (지시문 템플릿, 오탐 확인용) |
| `python tests/test_agent_client.py prompts/get summarize -a topic=revenue` | `PROMPT_CONTENT_INJECTION` |

### 7-2. 정의(definition) 포이즈닝 — 터미널 A를 `python tests/test_mcp_server.py --poison`으로 재시작

| 명령 | 기대 finding |
|---|---|
| `python tests/test_agent_client.py tools/list` | `TOOL_DEFINITION_INJECTION` (+ 정의가 바뀌었으면 `TOOL_DEFINITION_CHANGED`) |
| `python tests/test_agent_client.py resources/list` | `RESOURCE_DEFINITION_INJECTION` |
| `python tests/test_agent_client.py prompts/list` | `PROMPT_DEFINITION_INJECTION` |

`resources/list`는 한국어 리소스(`회의록`)가 있어 `ML_UNSUPPORTED_LANGUAGE`가 함께 붙습니다.

### 7-3. 차단까지 확인

Resp Policies 탭에서 finding=`RESOURCE_CONTENT_INJECTION`, action=`DENY` 정책 추가 →
Enforcement를 `ENFORCE`로 바꾸고 `notes.md`를 다시 읽으면 HTTP 403 (`MayAI response blocked by policy`).

### ML 끄기

ML을 테스트하지 않을 때 (API가 없어 DB 직접 수정):

```powershell
python -c "import os,sqlite3;c=sqlite3.connect(os.environ.get('NAC_DB_PATH','nac.db'));c.execute(\"UPDATE settings SET value='0' WHERE setting_key='ml_enabled'\");c.commit()"
```

## 8. 정리 / 초기화

```powershell
# 테스트 데이터만 지우기
Invoke-RestMethod -Method Delete "$api/api/logs" -Headers $h
Invoke-RestMethod -Method Delete "$api/api/policies" -Headers $h
Invoke-RestMethod -Method Delete "$api/api/response-policies" -Headers $h
Invoke-RestMethod -Method Delete "$api/api/agents" -Headers $h

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
- [ ] MAC: 상위 등급 접근 차단, 하위 등급 유출 차단, 라벨 없음 = L4, 세션 초기화 후 다시 허용
- [ ] 관리자 키 없이 변경 요청 → 401, 조회는 그대로 가능
- [ ] 신뢰: 의심 → 쓰기 차단, 침해 → 재실행해도 차단, 복구는 토큰 재설정 없이는 승인 거부
- [ ] 감사 로그 해시 체인 정상 표시
- [ ] `X-Agent-*` 헤더가 MCP 서버로 전달되지 않음 (코드상 제거됨 — 확인하려면 `tests/test_mcp_server.py`의 `do_POST`에서 `print(self.headers)`)

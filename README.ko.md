# AI-NAC 보안 게이트웨이

AI-NAC 코어 엔진(`nac-proxy.py`)의 단일 파일 구현입니다:

```
에이전트 인증 -> 프로토콜 검사기 (MCP/A2A) -> 보안 분석기
             -> 위험도 엔진 -> 정책 엔진 (판단) -> SQLite 로깅
```

여기에 더해 FastAPI 관리 API와 실제 트래픽 가로채기를 위한 mitmproxy 애드온을
제공합니다. SQLite DB(`nac.db`)는 최초 실행 시 자동으로 생성됩니다.

## 요구 사항

- Python 3.10+
- `pip install fastapi uvicorn` (모드 2에서 필요)
- `pip install mitmproxy` (모드 3에서만 필요)

이 PC에서 Python 경로는
`C:\Users\user\AppData\Local\Programs\Python\Python312\python.exe` 입니다.
`python`이 PATH에 없다면 터미널을 재시작하거나(사용자 PATH에는 이미 등록되어 있음)
전체 경로를 사용하세요. 아래 예시는 `python`을 기준으로 합니다.

```powershell
cd C:\Users\user\Desktop\scp
```

## 1. 셀프 테스트 (의존성 불필요)

어서션(assertion)으로 전체 판단 파이프라인을 점검합니다.

```powershell
python nac-proxy.py --selftest
# -> nac-proxy selftest: OK (all assertions passed)
```

## 2. 관리 API (FastAPI)

```powershell
python nac-proxy.py
```

- 대시보드: http://127.0.0.1:8000/  (에이전트·정책·트래픽·이벤트·위험도·평가 — `dashboard.html`, 빌드 불필요)
- Swagger UI: http://127.0.0.1:8000/docs
- 엔드포인트: `/api/agents`, `/api/policies`, `/api/logs`, `/api/events`,
  `/api/risk`, `/api/decisions/{request_id}`
- `/api/evaluate` 는 POST로 보낸 요청에 대해 mitmproxy 없이 전체 파이프라인을 실행합니다.

간단한 확인 방법 (서버가 실행 중인 상태에서, 두 번째 터미널):

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/evaluate `
  -H "Content-Type: application/json" `
  -d '{\"headers\":{},\"body\":{},\"destination\":\"x\"}'
# -> {"decision":"DENY","reason":"missing X-Agent-ID", ...}
```

## 3. 실제 트래픽 가로채기 (mitmproxy)

```powershell
pip install mitmproxy
python -m mitmdump -s nac-proxy.py -p 8080
```

그다음 AI 에이전트의 HTTP(S) 프록시를 `127.0.0.1:8080` 으로 지정합니다.

모든 요청에는 다음 헤더가 포함되어야 합니다:

```
X-Agent-ID: agent-001
X-Agent-Token: <token>
```

기본 정책은 **차단(deny)** 입니다. 먼저 API(모드 2)를 통해 에이전트를 등록하고
ALLOW 정책을 추가하지 않으면 모든 요청이 403으로 처리됩니다.

### 최소 설정 예시

```powershell
# 에이전트 등록
curl.exe -X POST http://127.0.0.1:8000/api/agents `
  -H "Content-Type: application/json" `
  -d '{\"agent_id\":\"agent-001\",\"agent_name\":\"Test\",\"token\":\"secret\",\"allowed_targets\":\"mcp-search\"}'

# 해당 에이전트가 mcp-search의 "search" 도구를 호출할 수 있도록 허용
curl.exe -X POST http://127.0.0.1:8000/api/policies `
  -H "Content-Type: application/json" `
  -d '{\"name\":\"allow-search\",\"agent_id\":\"agent-001\",\"protocol\":\"mcp\",\"target\":\"mcp-search\",\"tool\":\"search\",\"action\":\"ALLOW\",\"priority\":10}'
```

## 참고 사항

- `mitmdump` 와 `python nac-proxy.py` 는 동일한 `nac.db` 를 공유하므로, API로 추가한
  에이전트와 정책이 가로챈 트래픽에 즉시 적용됩니다.
- 범위 외(사양 기준): React 대시보드, 테스트용 MCP/A2A 서버, 공격 도구,
  Postgres/Redis/Docker.

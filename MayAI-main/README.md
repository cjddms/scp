# MayAI

MCP(Model Context Protocol) 보안 게이트웨이입니다. AI 에이전트와 MCP 서버 사이의 요청·응답을 검사해
정책에 따라 허용·차단하고, 모든 결정을 기록합니다.

- **HTTP 경로**: mitmproxy 애드온으로 외부 MCP 서버 트래픽을 검사합니다 (요청 정책, 응답 정책, ML 프롬프트 인젝션 탐지).
- **STDIO 경로**: 에이전트가 자식 프로세스로 띄우는 내부 MCP 서버 앞에 프록시로 붙습니다.
  요청 정책에 더해 **MAC(L1~L4 보안 등급)** 과 **에이전트 신뢰 상태(제로 트러스트)** 를 적용합니다.
- **관리 API + 대시보드**: `http://127.0.0.1:8000/` (변경 작업은 관리자 키 필요)

## 폴더 구조

```
MayAI-main/
├─ MayAI.py              # 게이트웨이 본체 (관리 API, mitmproxy 애드온, STDIO 프록시, 셀프 테스트)
├─ dashboard.html        # 대시보드 (MayAI.py가 같은 폴더에서 읽음)
├─ requirements-ml.txt   # ML 탐지용 선택 패키지
├─ models/prompt-injection/   # Llama Prompt Guard 2 (ONNX, model.onnx는 git 제외)
├─ docs/                 # 개발 명세, 테스트 가이드, ML 배포 계획
├─ examples/             # MCP 클라이언트 설정 예시(mcp.json), 모델 매니페스트 예시
├─ tests/                # 테스트용 MCP 서버, 가짜 에이전트, MAC·신뢰 데모
├─ ml/                   # 모델 평가·미세조정 스크립트, 데이터셋, 평가 결과
└─ legacy/scp/           # 이전 버전(nac-proxy.py) 보관
```

`nac.db`(정책·로그 DB)는 처음 실행할 때 자동으로 만들어지며 git에 올리지 않습니다.
위치는 `NAC_DB_PATH` 환경변수로 바꿀 수 있습니다.

## 빠른 시작

모든 명령은 `MayAI-main` 폴더에서 실행합니다.

```powershell
pip install fastapi uvicorn mitmproxy httpx2

python MayAI.py --selftest                      # 셀프 테스트

$env:NAC_DB_PATH = "$env:TEMP\nac-test.db"      # 테스트용 DB 분리 (권장)
$env:MAYAI_ADMIN_KEY = "test-admin-key"         # 관리자 키 (없으면 첫 실행 때 생성해 콘솔에 표시)
python MayAI.py                                 # 관리 API + 대시보드 :8000
mitmdump -s MayAI.py -p 8080                    # HTTP 검사 프록시
python tests/test_mcp_server.py                 # 테스트 MCP 서버 :9100
python tests/test_agent_client.py tools/list    # 가짜 에이전트 요청
python tests/test_mac_demo.py                   # STDIO MAC + 신뢰 상태 데모
```

자세한 시나리오는 [docs/TESTING_GUIDE.ko.md](docs/TESTING_GUIDE.ko.md)를 참고하세요.

## 알려진 문제

- STDIO 프록시에서 응답 ML 검사가 켜져 있을 때, 에이전트가 stdin을 열어 둔 채 다음 메시지를 보내지 않으면
  첫 허용 응답이 지연될 수 있습니다 (Windows에서 확인, 수정 예정). `tests/test_mac_demo.py`는 호출마다
  프록시를 새로 띄워 이 문제를 피하므로, 허용되는 단계는 30초~1분 걸릴 수 있습니다.

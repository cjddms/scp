"""Run only inside the Docker demo agent. Uses the separate demo database."""
import json
import sys
import urllib.error
import urllib.request
import uuid

ADMIN = 'http://admin:8000'
TARGET = 'target:9000'
AGENT = 'docker-demo-agent'
TOKEN = 'docker-demo-token'
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
proxied = urllib.request.build_opener(
    urllib.request.ProxyHandler({'http': 'http://proxy:8080'})
)


def api(path, data=None, method=None):
    request = urllib.request.Request(
        ADMIN + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type': 'application/json'}, method=method,
    )
    with direct.open(request, timeout=15) as response:
        return json.load(response)


def setup():
    if not any(a['agent_id'] == AGENT for a in api('/api/agents')):
        api('/api/agents', {'agent_id': AGENT, 'agent_name': 'Docker demo',
            'token': TOKEN, 'source_ip': '172.30.88.40', 'allowed_protocol': 'mcp'})
    names = {p['name'] for p in api('/api/policies')}
    for tool, action in [('search', 'ALLOW'), ('file_write', 'DENY'),
                         ('sensitive_search', 'ALLOW')]:
        name = 'docker-demo-' + tool
        if name not in names:
            api('/api/policies', {'name': name, 'agent_id': AGENT,
                'protocol': 'mcp', 'target': TARGET, 'tool': tool,
                'action': action, 'priority': 10})
    name = 'docker-demo-sensitive-response'
    if not any(p['name'] == name for p in api('/api/response-policies')):
        api('/api/response-policies', {'name': name, 'agent_id': AGENT,
            'protocol': 'mcp', 'target': TARGET, 'tool': 'sensitive_search',
            'finding': 'RESPONSE_SENSITIVE_DATA', 'action': 'DENY', 'priority': 10})
    print('Demo configuration ready. Existing records were not overwritten.')


def send(case):
    tool = {'allow': 'search', 'deny': 'file_write',
            'default-deny': 'unlisted_tool', 'bad-token': 'search',
            'missing-auth': 'search', 'sensitive': 'sensitive_search'}[case]
    headers = {'Content-Type': 'application/json'}
    if case != 'missing-auth':
        headers.update({'X-Agent-ID': AGENT,
                        'X-Agent-Token': 'incorrect' if case == 'bad-token' else TOKEN})
    request_id = str(uuid.uuid4())
    body = {'jsonrpc': '2.0', 'id': request_id, 'method': 'tools/call',
            'server': TARGET, 'params': {'name': tool, 'arguments': {'q': 'hello'}}}
    request = urllib.request.Request('http://' + TARGET + '/mcp',
        data=json.dumps(body).encode(), headers=headers)
    try:
        response = proxied.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.code
        text = response.read().decode()
    print(f'case={case} id={request_id} HTTP={status}\n{text}')
    if case == 'sensitive':
        print('Expected: MONITOR=200, ENFORCE=403. Inspect response records as well.')
    else:
        expected = 200 if case == 'allow' else 403
        if status != expected:
            raise SystemExit(f'FAIL: expected {expected}, got {status}')
        print('PASS')


if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else 'help'
    if command == 'setup':
        setup()
    elif command in ('monitor', 'enforce'):
        print(api('/api/settings/response-enforcement',
                  {'mode': command.upper()}, method='PUT'))
    elif command in ('allow', 'deny', 'default-deny', 'bad-token', 'missing-auth', 'sensitive'):
        send(command)
    else:
        raise SystemExit('Use setup, allow, deny, default-deny, bad-token, missing-auth, monitor, enforce, sensitive')

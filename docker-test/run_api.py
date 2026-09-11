import runpy
import uvicorn

engine = runpy.run_path('/app/nac-proxy.py', run_name='nac_engine')
engine['init_db']()
uvicorn.run(engine['build_api'](), host='0.0.0.0', port=8000)

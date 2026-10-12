from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from rootiq import service

app = FastAPI(title="RootIQ", version="0.1")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).parent / "dashboard.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/runs")
def runs():
    return service.list_runs()


@app.get("/runs/{run_id}")
def run_analysis(run_id: str):
    result = service.analyze_run(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"{run_id} not found")
    return result


@app.get("/flaky")
def flaky():
    return service.flaky_report()
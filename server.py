from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ScanBody(BaseModel):
    email_text: str

@app.post("/scan")
def scan(b: ScanBody):
    # TODO: replace this stub with your real scoring logic
    return {
        "score": 90,
        "heuristic_score": 100,
        "verdict": "ok",
        "urls_found": [],
    }

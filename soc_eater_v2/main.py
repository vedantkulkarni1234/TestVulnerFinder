"""SOC-EATER v2 - FastAPI + Gradio entrypoint.

Run:
  pip install -r requirements.txt
  export GEMINI_API_KEY=...
  python soc_eater_v2/main.py
"""

from __future__ import annotations

import io
import os
from typing import Any, Optional

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import gradio as gr
from PIL import Image

from soc_eater_v2.soc_brain import SOCBrain
from soc_eater_v2.utils.pcap_parser import summarize_pcap_bytes


class AnalyzeJSONRequest(BaseModel):
    prompt: str
    context: Optional[dict[str, Any]] = None


class RunPlaybookRequest(BaseModel):
    incident_data: dict[str, Any]


def create_app() -> FastAPI:
    app = FastAPI(title="SOC-EATER v2", version="2.0.0")
    brain = SOCBrain(api_key=os.getenv("GEMINI_API_KEY"))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "model": "gemini-1.5-flash"}

    @app.get("/playbooks")
    def playbooks() -> dict[str, Any]:
        return {"playbooks": brain.list_playbooks()}

    @app.post("/playbooks/{playbook_id}/run")
    def run_playbook(playbook_id: str, body: RunPlaybookRequest) -> JSONResponse:
        result = brain.run_playbook(playbook_id, body.incident_data)
        return JSONResponse(result)

    @app.get("/stats")
    def stats() -> dict[str, Any]:
        return brain.get_stats()

    @app.post("/analyze_json")
    def analyze_json(body: AnalyzeJSONRequest) -> JSONResponse:
        result = brain.analyze_incident(prompt=body.prompt, context=body.context)
        return JSONResponse(result)

    @app.post("/analyze")
    async def analyze(
        prompt: str = Form(...),
        context_json: Optional[str] = Form(None),
        file: Optional[UploadFile] = File(None),
    ) -> JSONResponse:
        context = None
        if context_json:
            import json

            try:
                context = json.loads(context_json)
            except Exception:
                context = {"raw_context": context_json}

        images = None
        if file is not None:
            content = await file.read()
            filename = (file.filename or "").lower()
            content_type = (file.content_type or "").lower()

            if content_type.startswith("image/") or filename.endswith((".png", ".jpg", ".jpeg", ".webp")):
                img = Image.open(io.BytesIO(content)).convert("RGB")
                images = [img]

            elif filename.endswith((".pcap", ".pcapng")) or content_type in {
                "application/vnd.tcpdump.pcap",
                "application/octet-stream",
            }:
                pcap_summary = summarize_pcap_bytes(content, max_packets=4000)
                prompt = (
                    f"{prompt}\n\n[PCAP SUMMARY]\n{pcap_summary}\n\n"
                    "Use the PCAP SUMMARY to extract IOCs, timeline, and likely attack narrative."
                )

            else:
                prompt = (
                    f"{prompt}\n\n[FILE ATTACHMENT]\nFilename: {file.filename}\nContent-Type: {file.content_type}\n"
                    "The attachment could not be parsed. Proceed using all available context."
                )

        result = brain.analyze_incident(prompt=prompt, context=context, images=images)
        return JSONResponse(result)

    def gradio_analyze(user_prompt: str, upload: Any):
        images = None
        prompt = user_prompt

        if upload is not None and isinstance(upload, str):
            path = upload
            lowered = path.lower()
            if lowered.endswith((".png", ".jpg", ".jpeg", ".webp")):
                img = Image.open(path).convert("RGB")
                images = [img]
            elif lowered.endswith((".pcap", ".pcapng")):
                with open(path, "rb") as f:
                    pcap_summary = summarize_pcap_bytes(f.read(), max_packets=4000)
                prompt = (
                    f"{prompt}\n\n[PCAP SUMMARY]\n{pcap_summary}\n\n"
                    "Use the PCAP SUMMARY to extract IOCs, timeline, and likely attack narrative."
                )

        result = brain.analyze_incident(prompt=prompt, images=images)
        return result.get("raw_analysis", "")

    demo = gr.Interface(
        fn=gradio_analyze,
        inputs=[
            gr.Textbox(
                label="Incident / alert / prompt",
                lines=10,
                placeholder="Paste alert, log, IOC list, phishing report, etc.",
            ),
            gr.File(label="Optional upload (image / PCAP)"),
        ],
        outputs=gr.Markdown(label="SOC Report"),
        title="SOC-EATER v2",
        description="Gemini 1.5 Flash-powered SOC automation: triage → investigation → report.",
    )

    app = gr.mount_gradio_app(app, demo, path="/")
    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "soc_eater_v2.main:create_app",
        factory=True,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=False,
        log_level=os.getenv("LOG_LEVEL", "info"),
    )

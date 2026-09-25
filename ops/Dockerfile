FROM python:3.12-slim

# Fraud scoring model is pulled from a private Hugging Face repo at build time
# so the runtime image has no network access to the model host.
# TESTBED SEC-17 - intentional, see EXPECTED_FINDINGS.md
ENV HF_TOKEN=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

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/ledger

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

RUN python -c "from huggingface_hub import snapshot_download; \
    snapshot_download('acme-ledger/fraud-scorer', token=__import__('os').environ['HF_TOKEN'])" || true

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

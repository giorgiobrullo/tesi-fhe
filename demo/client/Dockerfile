# Il CLIENT del varco: il terminale fidato. Ha il modello di riconoscimento (in chiaro) e la
# chiave segreta; serve la pagina con la telecamera. Contesto di build: la radice del repo.
FROM rust:1-bookworm AS rust
WORKDIR /src
COPY experiments/14_pipeline_tfhe_rs/Cargo.toml experiments/14_pipeline_tfhe_rs/Cargo.lock ./
COPY experiments/14_pipeline_tfhe_rs/src ./src
RUN cargo build --release --bin varco_demo

FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake libgl1 libglib2.0-0 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy==1.26.4 onnxruntime insightface fastapi uvicorn \
        imageio scikit-image pydantic
COPY --from=rust /src/target/release/varco_demo /usr/local/bin/varco_demo
WORKDIR /app
COPY demo /app/demo
COPY experiments/08_cnn/embedding.py /app/experiments/08_cnn/embedding.py
COPY core /app/core
ENV VARCO_SERVER=http://server:9000 VARCO_BIN=/usr/local/bin/varco_demo VARCO_CHIAVI=/app/chiavi \
    PYTHONPATH=/app INSIGHTFACE_HOME=/root/.insightface
EXPOSE 8000
CMD ["uvicorn", "demo.client.app:app", "--host", "0.0.0.0", "--port", "8000"]

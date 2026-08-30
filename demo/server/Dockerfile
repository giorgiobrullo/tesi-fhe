# Il SERVER del varco: un solo binario Rust, nessun modello, nessuna chiave segreta.
# Contesto di build: la radice del repo (serve experiments/14_pipeline_tfhe_rs).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY experiments/14_pipeline_tfhe_rs/Cargo.toml experiments/14_pipeline_tfhe_rs/Cargo.lock ./
COPY experiments/14_pipeline_tfhe_rs/src ./src
# niente target-cpu=native: l'immagine deve girare anche su un'altra macchina
RUN cargo build --release --bin varco_demo

FROM debian:bookworm-slim
COPY --from=build /src/target/release/varco_demo /usr/local/bin/varco_demo
ENV DIM=512 SOGLIA=23 LOG_DELTA=52 PORTA=9000
EXPOSE 9000
# il server riceve la chiave di VALUTAZIONE dal client all'avvio; la segreta non la vede mai
CMD ["sh", "-c", "varco_demo serve $PORTA $DIM $SOGLIA $LOG_DELTA"]

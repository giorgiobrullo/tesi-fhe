# 13 — Separare il costo degli score da quello dell'argmin

Il [torneo Concrete](../10_argmin_struttura/README.md) era più rapido della
catena, ma ancora lento. Qui si è riscritta una prima pipeline in TFHE-rs:
**calcolare gli score** della query cifrata contro template pubblici e
**scegliere il minimo**. Separare i due tempi rivela dove intervenire dopo.

Con l'API ad alto livello `FheInt16`, a N=8 l'argmin richiede **1,78 s**, ma
l'intera pipeline **100,6 s**: circa 99 s sono nel calcolo degli score.
Il rapporto storico di circa 100× fra argmin Concrete e TFHE-rs non misura
un guadagno equivalente dell'applicazione: i due programmi usano domini di
punteggio diversi e l'attribuzione della macchina usata per il riferimento
Concrete è incerta. Il [report](RISULTATI.md) conserva queste riserve.

La prova successiva [`basso_livello.rs`](src/bin/basso_livello.rs) esegue il
prodotto scalare usando primitive LWE grezze: combina la query cifrata con
coefficienti pubblici, senza propagare riporti con bootstrap. La misura
storica arriva a **2,0 ms per 64 score**. È una prova del solo calcolo
lineare, con parametri scelti a mano **non validati a 128 bit**; non è la
latenza di un'identificazione completa.

L'argmin ad alto livello viene inoltre confrontato con l'atteso in 208 casi
nel programma [`correttezza.rs`](src/bin/correttezza.rs). Il passo successivo,
[esperimento 14](../14_pipeline_tfhe_rs/README.md), sviluppa la pipeline
esatta con primitive a basso livello e parametri standard. I
[sorgenti Rust](src/main.rs) e il [report](RISULTATI.md) distinguono i
test di componente da quelli dell'intera pipeline.

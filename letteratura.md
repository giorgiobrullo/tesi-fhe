# Letteratura — riconoscimento facciale cifrato 1:N veloce e accurato

Rassegna mirata al **nostro collo di bottiglia**: l'argmin/argmax cifrato per
l'identificazione 1:N open-set (controllo accessi). Domanda: come fanno gli altri a
renderlo veloce (secondi) e accurato, e quale schema FHE usano?

> Fonti raccolte con una ricerca multi-sorgente (deep-research, 16 fonti primarie/secondarie,
> 78 affermazioni estratte, 25 verificate). Lo stadio di sintesi automatica è fallito → i
> numeri qui sotto sono letti **direttamente dai paper**.

## Tesi centrale: usano CKKS, non TFHE
La quasi totalità dei sistemi 1:N facciali cifrati usa **CKKS** (Cheon-Kim-Kim-Song).
Motivo: CKKS opera su vettori di reali con **packing SIMD** — una operazione cifrata
agisce su centinaia di slot in parallelo. Si impacchettano *tutte* le similarità della
galleria in un ciphertext e si batchano i confronti. TFHE/Concrete è ottimo per funzioni
non-lineari arbitrarie (PBS) ma paga l'argmax come **riduzione sequenziale** → il nostro
muro (findings F25/F26). Il problema non era la FHE, era lo **schema** scelto per questo
compito.

## Sistemi chiave (con numeri)

### Blind-Match — CCS 2024
- URL: https://arxiv.org/abs/2408.06167 · https://arxiv.org/html/2408.06167v2
- Schema: **CKKS** (Lattigo v5, N=8192, ~128-bit security).
- Metodo: **partizionamento del feature vector + packing SIMD**; impacchetta più identità
  per ciphertext (256 feature vector confrontati simultaneamente con N=8192, m=128, N_in=4).
- Numeri: **737 ms totali per 6.144 campioni** (452 ms matching + enc/dec + rete) →
  **~0,073 ms per identità**; **3,5× più veloce** della cosine-similarity HE convenzionale.
- Accuratezza: **LFW rank-1 99,63%** (128-dim); impronte PolyU 99,68%. Backbone ResNet-18 +
  ArcFace su Glint360k.
- **Chi fa l'argmax: il CLIENT.** Il server ritorna un singolo ciphertext compresso con
  tutte le similarità; il client decifra e trova l'indice del massimo.
- Leakage: server cieco (IND-CPA, vede solo la lunghezza, costante); il client vede i
  punteggi. → **È il nostro modello F22 fatto con lo schema giusto.**

### Mazzone et al. — "Efficient Ranking, Order Statistics, and Sorting under CKKS" — USENIX Security '25
- URL: https://arxiv.org/abs/2412.15126
- Schema: **CKKS**. Re-encoding del vettore sotto cifratura per confrontare **tutti gli
  elementi tra loro simultaneamente** (SIMD), profondità di confronto **costante (≤2)** vs
  k·log²N dello stato dell'arte precedente.
- Numeri: ranking di 128 elementi ~**5,76 s**; **argmin/argmax ~12,83 s**; sorting ~78,64 s.
- Rilevanza: è l'**argmax cifrato server-side, privato (nessun leakage)**, allo stato
  dell'arte. Per noi: N=128 in ~13 s, contro ~120 s di TFHE per N=8.

### GROTE — "Group testing for privacy-preserving face identification" — CODASPY 2023
- Autori: Ibarrondo, Chabanne, Despiegel, Önen (EURECOM/Idemia).
- URL: https://www.eurecom.fr/en/publication/7213
- Schema: **CKKS**. Sostituisce il test elemento-per-elemento con **group testing** →
  riduce i confronti non-lineari da **n a ~2√n**. Approssima il max via potenza p-esima +
  somma cumulativa in layout 2D (piccolo impatto sull'accuratezza).
- Rilevanza: la **leva algoritmica** per abbattere il costo dell'argmax server-side.

### HERS — "Homomorphically Encrypted Representation Search" — Engelsma, Jain & Jain
- URL: https://arxiv.org/abs/2003.12197
- Ricerca su template cifrati che scala a **100 milioni** di volti in **~500 s**, **275×**
  più veloce dello stato dell'arte sulla ricerca cifrata. Su galleria piccola → millisecondi.
- Rilevanza: dimostra che col packing la ricerca è quasi gratis **per-item**; il costo è
  dominato dalla scala, non dalla singola similarità.

## Le due strade (e la raccomandazione)

**(A) "Client decide" — stile Blind-Match.** CKKS, similarità coseno impacchettate, server
ritorna un ciphertext, **argmax sul client in chiaro**. ~ms, ~99,6%. Coincide col nostro
F22 (server cieco). Limite: il client vede i punteggi (leakage accettato in letteratura,
server honest-but-curious). → **Il sistema veloce-e-accurato cercato.**

**(B) "Client non fidato"** (il nostro vincolo duro). Argmax sul server, privato:
**CKKS-SIMD argmax** (Mazzone, ~13 s per N=128) **+ group testing GROTE** (n→2√n).
Server-side e in secondi, dove TFHE era a minuti.

**Adottabilità.** Concrete = TFHE → per questa parte serve una libreria **CKKS**
(OpenFHE / Lattigo / Microsoft SEAL). Risultato di tesi già forte: *abbiamo dimostrato
misurando che TFHE/Concrete sbatte sul muro dell'argmax, mentre la letteratura lo risolve
con CKKS + packing SIMD (+ group testing)*. Prossimo passo: prototipo CKKS della
galleria-1:N (cosine similarity impacchettata) vs il nostro TFHE.

## Altre fonti raccolte (da vagliare)
- https://arxiv.org/abs/2003.12197 — HERS (primaria)
- https://dl.acm.org/doi/10.1145/3577923.3583656 — (ACM, identificazione cifrata)
- https://www.mdpi.com/2410-387X/8/2/18 — Cryptography (argmax/confronti cifrati)
- https://www.mdpi.com/1424-8220/23/7/3566 — Sensors (FHE vs MPC vs template protection)
- https://www.sciencedirect.com/science/article/abs/pii/S0167404824006151 — Computers & Security (comparativa)
- https://link.springer.com/chapter/10.1007/978-3-031-95767-3_4 — Springer (template protection)
- https://arxiv.org/abs/2104.02239 — (biometria + HE)
- https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0314656 — PLOS ONE
- https://hal.science/hal-04000209 — scelta schema TFHE vs CKKS (accesso bloccato in fetch)

# Benchmark per "facce reali" — scelta dei dataset (nota di riferimento)

Perché questa nota: LFW è **saturo** (le CNN moderne fanno >99% in verifica),
quasi-frontale e demograficamente sbilanciato → va bene come *sanity-check*, non come
prova dura. Il nostro caso d'uso è il **controllo accessi a un varco**: galleria di
iscritti autorizzati, **identificazione 1:N open-set** con **rifiuto degli sconosciuti**
(impostori) — esattamente la galleria + soglia del gradino 06. Servono dataset che
riflettano acquisizioni reali e varie (sorveglianza, bassa risoluzione, distanza, posa
e luce non controllate) e che **non siano saturati** dalle CNN.

> Fonte: ricerca approfondita multi-fonte con verifica adversariale dei claim
> (23/25 confermati). Citazioni puntuali in fondo.

## La metrica giusta: TPIR@FPIR (non Rank-k)

Per il controllo-accessi open-set la metrica corretta è la **TPIR a un FPIR basso
fisso** (es. `FPIR = 0,01%`): misura insieme le identificazioni corrette *e* il rifiuto
degli sconosciuti. Il **Rank-k closed-set (CMC)** assume che il probe sia sempre
iscritto → non misura il rifiuto degli impostori, quindi è inadatto. (NIST FRVT
NISTIR 8381, ISO/IEC 19795-1:2021. CMC(r) è il caso speciale di TPIR a FPIR=1.)

**Aggancio alla nostra pipeline:** FPIR ↔ la **soglia sulla distanza euclidea cifrata**
lato server (gradino 06). Abbassare la soglia = meno falsi accessi (FPIR↓) ma più
rifiuti di iscritti veri (FNIR↑). È la stessa soglia open-set, vista come curva DET.

## I candidati

| dataset | cosa lo rende duro | protocollo | accesso | dimensione | note |
|---|---|---|---|---|---|
| **QMUL-SurvFace** | bassa risoluzione **nativa** da CCTV (media 24×20 px), blur, rotazioni | **1:N open-set nativo** (watch-list 3.000 gallery vs ~10.254 probe, ~70% sconosciuti) | **libero** (GitHub) | 463.507 img / 15.573 ID | il "vero" hard. CentreFace 65,2%→**29,9%** Rank-1; non saturato |
| **SCface** | mug-shot puliti (gallery) vs probe di sorveglianza a **3 distanze** (1,0/2,6/4,2 m), luce/qualità varie, camera dall'alto | gallery mug-shot vs probe sorveglianza (closed-set; adattabile open-set) | **licenza accademica** (email) | 130 sogg / 4.160 img | modella *letteralmente* "riferimento pulito vs acquisizione al varco". Bias: 114M/16F, no non-caucasici, quasi-frontale |
| **TinyFace** | bassa risoluzione **nativa** (media 20×16 px), web non controllato | 1:N con tutte le immagini non etichettate come **distrattori** | **libero** (GitHub) | 169.403 img / 5.139 ID | utile per scala/distrattori |
| **IJB-S** | video sorveglianza reali, altitudine/distanza varie, UAV | **1:N open-set nativo**, TPIR@FPIR, 5 esperimenti | **licenza IARPA** (ristretta) | 202 sogg / 350 video | il più realistico, ma scenari recitati DoD e accesso difficile |
| **IJB-C** | mixed-media in-the-wild | **1:N open-set nativo** (Test 4), TPIR@FPIR | **ritirato** (NIST, 2023-03-14) | 3.531 sogg | usare solo come *specifica del protocollo* |
| LFW | (riferimento) | verifica 1:1 | libero (sklearn) | — | **saturo** → solo baseline/sanity |

Ritirati / non disponibili: **MS-Celeb-1M** (consenso/privacy), **MegaFace** (UW).

## Raccomandazione per la tesi

Una **scala di difficoltà** (coerente con lo spirito "scaletta crescente" del progetto),
non un singolo set:

1. **LFW** — sanity-check facile (lo abbiamo già). Mostra che la pipeline funziona.
2. **SCface** — *set duro primario* per il controllo-accessi. Modella esplicitamente il
   mismatch galleria-pulita / probe-al-varco, ha un **gradiente di difficoltà** built-in
   (3 distanze) ottimo per mostrare le tecniche che salgono, ed è **piccolo e
   maneggevole**. Richiede registrazione accademica (ok, hai detto licenza accettabile).
3. **QMUL-SurvFace** — *riferimento estremo*, libero, open-set 1:N nativo, non saturato.
   ⚠️ A 24×20 px nativi è **brutalmente duro**: i metodi semplici (e perfino ArcFace
   off-the-shelf) rischiano di crollare al *pavimento* — informativo come limite, ma non
   come gradiente. Da usare per dire "ecco dove si rompe tutto".

Metrica primaria ovunque: **TPIR@FPIR**.

Perché SCface come primario e non SurvFace (che il report metteva primo): per uno
**studio di fattibilità che sale di tecnica**, un set dove *tutto* fallisce (~single
digit) è informativo quanto uno saturo. SCface dà un gradiente leggibile (distanza
crescente) e modella il varco alla lettera; SurvFace resta come "estremo".

## Caveat onesti (da scrivere in tesi)

- **Nessun dataset di kiosk cooperativo puro.** SurvFace/TinyFace sono footage di
  persone in movimento (re-ID/web); SCface/IJB-S modellano il mismatch
  galleria/probe ma non sono "persona che presenta il volto a un varco". È
  un'interpretazione applicata, non un dataset dedicato (non esiste/non emerso).
- **Fairness e posa/età non verificati.** La domanda chiedeva anche RFW /
  BUPT-Balancedface / FairFace / CPLFW / CALFW / CFP-FP / AgeDB-30, ma la verifica
  adversariale **non** ha confermato claim su questi → non li raccomandiamo con
  evidenza. Lacuna da colmare se la fairness diventa un requisito. (SCface stesso ha
  forte bias demografico.)
- **Crop minuscoli ⇒ problema FHE.** SurvFace/TinyFace sono 20-24 px: l'allineamento
  ArcFace 112×112 RGB richiede **super-risoluzione o un modello cross-resolution**, non
  un semplice resize. E più upscaling/precisione = più bit per valore = **leva di costo
  esponenziale FHE** (F1–F3). Tensione concreta tra "set duro realistico" e costo FHE.

## Passi pratici

- **QMUL-SurvFace / TinyFace**: pagine GitHub pubbliche (`qmul-survface.github.io`,
  `qmul-tinyface.github.io`), download diretto.
- **SCface**: accordo di licenza via `scface.org` (modulo + email accademica).
- Pipeline: allineamento volti (MTCNN/insightface) → per i crop piccoli, upscaling o
  modello cross-resolution → embedding → quantizzazione → cifratura (la nostra
  pipeline). Per i descrittori locali (LBP/HOG) attesa **caduta forte** su questi set:
  è il punto.

## Fonti

- QMUL-SurvFace: https://qmul-survface.github.io/ · paper arXiv 1804.09691 · Massoli et al. arXiv 1912.02851
- SCface: https://www.scface.org/ · Grgic et al., MTAP 2011 (10.1007/s11042-009-0417-2)
- TinyFace: https://qmul-tinyface.github.io/ · arXiv 1811.08965
- IJB-S: Kalka et al., BTAS 2018 (IEEE 8698584) · survey arXiv 2505.24247
- IJB-C: README NIST/IARPA · ritiro NIST 2023-03-14
- Metrica open-set: NIST FRVT https://pages.nist.gov/frvt/reports/1N/ · ISO/IEC 19795-1:2021
- Saturazione LFW/CFP-FP: survey arXiv 2505.24247

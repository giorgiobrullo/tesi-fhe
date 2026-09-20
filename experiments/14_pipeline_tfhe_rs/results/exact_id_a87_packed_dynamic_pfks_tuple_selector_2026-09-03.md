# A87 - selettore dinamico packed per tuple PFKS A30

Data: 2026-09-03  
Ambito: prova statica nel ring plaintext e ledger strutturale; nessun Cargo,
keygen, carico FHE o benchmark.

## Domanda

Nel piano A30 scalar ogni nodo non-root deve selezionare cifratamente quattro
payload - tre limb dello score e l'ID - e quindi ripete quattro volte la blind
rotation dinamica. Si può costruire un solo accumulatore cifrato contenente
l'intera tuple e ottenere i quattro payload con una sola blind rotation più
quattro sample extraction?

## Esito

**GO statico per geometria e conteggi. NO-GO per promozione alla frontiera
runtime finché il gate FHE non misura correttezza, rumore e latenza.**

La costruzione usa i controlli p16 già previsti da A30, centro 4 per scegliere
left e centro 12 per right. Per il payload `j` estrae al grado `j*128`. I centri
virtuali delle due celle sono quindi:

```text
left_j  = 4*128  + j*128
right_j = 12*128 + j*128
```

Ogni payload viene portato da LWE a un GLWE che cifra il monomio costante,
moltiplicato per una maschera pubblica firmata di larghezza 127, e sommato agli
altri. I segni compensano esattamente il wrap di
`Z/(2^64)[X]/(X^2048+1)`. Dopo la rotazione cifrata, i campioni ai gradi
`0,128,256,...` restituiscono tutta la tuple selezionata.

## Prova eseguita

| Controllo | Risultato |
|---|---:|
| Lunghezze provate esaustivamente | k=1..8 |
| Errori di rotazione per controllo | tutti i 127 valori -63..+63 |
| Controlli | left=4, right=12 |
| Confronti torus esatti D2 | 9.144 |
| Confronti torus esatti D1 | 9.144 |
| Fuzz deterministico u64 | 4.096 tuple |
| Word verificate dal fuzz, per variante | 18.252 |
| Composizioni tie/reject | 920 |
| Score bridge confrontati con A30 pin-nato | 4.096 |
| Maschere pubbliche materializzate e content-addressed | 16 |
| Source pin | 9 |
| Test | 17/17 PASS |
| Ruff | PASS |

Il confronto è sui word torus u64 esatti e include scale miste. Per il caso A30
reale, la tuple non-root è
`(limb0@2^59, limb1@2^59, limb2@2^59, id@2^56)`; la root propaga solo l'ID.
La composizione del comparatore è confrontata anche con l'oracolo A30 pin-nato,
inclusi tie-left, sentinel, confine 1023/1024, torneo ragged e ID 127.

Il contratto exact-ID e il ledger sono congelati a `1<=N<=127`, con casi ragged
dedicati a `N=33,63,64,65,126`. Per `N>127` questo artefatto non prova né la
codifica ID più larga, né il contratto, né i conteggi conseguenti.

Durante la costruzione della suite un primo draft aveva invertito il segno del
controllo del comparatore e sceglieva il sentinel invece dello score valido. Le
fixture `(0,0)` lo hanno rifiutato; la versione congelata confronta esplicitamente
tutti i 4.096 bridge key e i 27 pattern ternari con A30. Questo è anche il motivo
per cui l'esito non si basa soltanto sull'auto-consistenza del nuovo modello.

## Conflitto nascosto cercato

Non c'è collisione fra le celle ripiegate per `k<=8`. A `k=8`, le sedici celle
occupano 2.032 coefficienti su 2.048: ogni cella usa i 127 indici del suo plateau
e resta un coefficiente di guardia fra celle adiacenti.

La prima collisione è riproducibile a `k=9`: `left_j8` e `right_j0` chiedono
entrambi il centro virtuale 1536. Quindi otto è il massimo di **questa** scelta
di controlli, passo di estrazione e celle disgiunte; non è un upper bound
universale. Anche `±64` è deliberatamente fuori contratto e il report conserva
controesempi. Una maschera senza correzione di segno fallisce appena il centro
attraversa 2048.

## Ledger indipendente a N=127

| Piano B0, root ID-only | BR | KS classici | marginals | PFKS | poly mul | GLWE add | LWE pre-sub | LWE post-add |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A30 scalar D2 corrente | 2.664 | 2.283 | 3.553 | 1.010 | 1.010 | 505 | 0 | 0 |
| A87 packed D2 | **2.286** | **1.905** | 3.553 | 1.010 | 1.010 | 883 | 0 | 0 |
| A87 packed D1 | **2.286** | **1.905** | 3.553 | 505 | 505 | 378 | 505 | 505 |

Il packed D2 sostituisce `4N-3=505` rotazioni dinamiche con `N=127` rotazioni:
**-378 BR e -378 KS** rispetto ad A30 scalar. PFKS, moltiplicazioni pubbliche e
sample extraction restano invariati; si spendono 378 somme GLWE aggiuntive, ma
ci sono 378 input logici accumulatore/BR del selettore in meno; non è un conteggio
di oggetti allocati concreti. Rispetto ad A62 il ledger packed D2 è
più basso di 1.104 BR, 1.104 KS e 377 marginals, con 1.010 PFKS aggiuntive
rispetto a un percorso che non le usa.

La variante D1 calcola prima `right-left` con una sottrazione LWE per output,
porta il delta con una sola PFKS per payload, lo mette solo nelle celle right e
somma left con una addizione LWE dopo l'estrazione. A `N=127` sono quindi 505
sottrazioni preselection e 505 addizioni postselection (`5+5` a `N=2`). Questo
dimezza le PFKS a 505 senza cambiare BR/KS/marginals, ma resta secondaria: la sua
identità clear non certifica cancellazione e rumore FHE.

## Evidenza sorgente

Sono pin-nati per SHA-256:

1. design, modello clear e scaffold Rust D2 di A30;
2. il codice Cong per PFPKS LWE→GLWE, moltiplicazione polinomiale e somma D2;
3. il preflight A86, mantenuto soltanto come screen advisory;
4. algoritmo e keygen private-functional packing KS di TFHE-rs 0.11.3;
5. moltiplicazione nel ring e sample extraction TFHE-rs 0.11.3.

In particolare lo scaffold A30 fissa il polinomio identity al solo coefficiente
zero e la funzione di segno complementare; il keygen TFHE-rs pin-nato lega quel
polinomio ai blocchi decomposti. Questo rende concreta la premessa “PFKS verso
GLWE costante” a livello sorgente, non a livello di esecuzione.

## Limiti che impediscono la promozione

- Nessun ciphertext ha eseguito questa nuova geometria; non sono attestati
  semantica runtime PFPKS, FFT, blind rotation o sample extraction congiunti.
- Gli output condividono accumulatore, control LWE, bootstrap e PFPK riusata:
  gli errori sono correlati e non si possono moltiplicare probabilità marginali.
- Il supporto quadratico esatto delle maschere D2 non-root è `8*127=1.016`,
  contro `2*1024=2.048` nello screen scalar A86. Questa riduzione non determina
  il rumore senza covarianze e decomposizione PFPKS reali.
- L'ID usa la scala più debole `Delta=2^56`; deve essere decifrato e misurato.
- D1 somma left rumoroso al delta selezionato rumoroso e richiede un audit
  separato della correlazione/cancellazione.
- I conteggi non dicono quanto costino davvero otto PFKS, otto FFT polynomial
  multiply, sette somme GLWE, una KS/BR e quattro extraction.

Pertanto il JSON mantiene esplicitamente
`promotion_to_a30_runtime_frontier_allowed=false`.

## Gate successivo

Estendere in isolamento lo scaffold A30 con D2 `k=4`, senza integrare ancora la
pipeline completa. Per entrambe le fasi control e per fixture di bordo bisogna:

1. decifrare tutti e quattro gli output con le scale rispettive;
2. misurare separatamente 8 PFKS, 8 polynomial multiply, 7 GLWE add, control
   KS, blind rotation e 4 sample extraction;
3. registrare phase error congiunti, non soltanto pass/fail marginali;
4. ripetere in processi/chiavi freschi sui parametri A86 ordinati;
5. testare D1 solo dopo il pass causale di D2.

Il prototipo e il verificatore specifici di questa analisi non sono inclusi
nella distribuzione.

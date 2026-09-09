# A29 vs A33: benchmark appaiato exact-ID

Data run: 2026-09-02T11:56:16Z--12:47:17Z. Durata wall: 3.061,481 s.

## Esito

**PASS nel perimetro del confronto appaiato.** A33 conserva il contratto exact-ID e, nelle 120
coppie misurate, riduce la latenza server geometrica del **13,734%** rispetto ad A29
(`A33/A29 = 0,862657`, circa **1,159x**). L'intervallo bootstrap al 95% osservato in questo run e'
**[11,806%, 15,595%]**.

| misura primaria | A29 | A33 | confronto appaiato |
|---|---:|---:|---:|
| PBS/blind rotation per query | 4.965 | 4.273 | -692 (-13,94%) |
| latenza server media | 11.328,525 ms | 9.803,585 ms | delta medio -1.524,940 ms |
| latenza server mediana | 10.813,350 ms | 9.364,650 ms | delta appaiato mediano -1.540,100 ms |
| vittorie | 15/120 | 105/120 | nessun pareggio |

La mediana delle riduzioni appaiate e' 15,054%. La riduzione ottenuta confrontando separatamente le
due mediane, 13,397%, e' secondaria: l'estimando preregistrato e' la media geometrica dei rapporti
appaiati `A33/A29`.

La riduzione strutturale dei blind rotation, `692/4.965 = 13,938%`, differisce dalla riduzione di
latenza osservata di soli **0,203 punti percentuali** ed e' interna al CI del run. Questa
corrispondenza e' coerente con i blind rotation come costo dominante nel confronto A29/A33; non
dimostra pero' una legge lineare trasferibile ad altri circuiti, macchine o livelli di parallelismo.

## Accordo semantico exact-ID

Le 120 coppie misurate e le 24 di warm-up escluse dalla statistica temporale producono **zero
discrepanze semantiche**. Entrambe le implementazioni restituiscono sempre un solo LWE col contratto
`exact-open-set-id-v2`: `0` rifiuta, mentre `i+1` identifica la prima identita' col minimo accettato.

| probe | minimo clear | primo argmin clear | codice atteso | A29 | A33 |
|---:|---:|---:|---:|---:|---:|
| 265 | 2 | 17 | 18 | 18 | 18 |
| 758 | 3 | 45 | 46 | 46 | 46 |
| 211 | 4 | 92 | 93 | 93 | 93 |
| 1943 | 5 | 82 | 0 | 0 | 0 |
| 407 | 7 | 81 | 0 | 0 | 0 |

La soglia e' inclusiva (`T=4`): i minimi 2, 3 e 4 vengono accettati con l'identita' precisa; 5 e
7 vengono rifiutati. Il probe `758`, codice `46`, e' il falso positivo biometrico noto previsto
dall'oracolo, non un errore FHE.

I 144 probe ciphertext sono tutti distinti fra coppie e byte-identici fra A29 e A33 dentro la
stessa coppia. Anche i 144 output ciphertext di ciascuna implementazione hanno hash distinti. In
ogni blocco i due server ricevono la stessa chiave di valutazione, la stessa galleria ordinata, lo
stesso dominio stretto `[-987, 2329]` e la stessa soglia; il percorso A33 e il suo dominio di
esecuzione allineato `[-1019, 2329]` vengono inoltre verificati indipendentemente.

## Disegno del confronto

Il run finale comprende sei blocchi sequenziali, ciascuno con una coppia di chiavi fresca. Tutte le
cifrature di un blocco sono terminate prima di avviare i due server e la decifratura e' rimandata
finche' non sono concluse tutte le coppie temporizzate, evitando che cifratura e decifratura
entrino nella misura server.

Per ciascun blocco:

- 4 coppie di warm-up vengono eseguite e poi escluse;
- 20 coppie entrano nell'analisi;
- ognuno dei cinque probe compare quattro volte, due in ordine A29->A33 e due A33->A29;
- l'ordine di avvio dei server alterna fra i blocchi.

In totale sono 120 coppie misurate e 24 warm-up, su sei chiavi di valutazione distinte. La
decifratura usa il client A33 congelato, compatibile col formato di output di entrambe le varianti.
Alla fine tutti i server sono terminati, le porte risultano chiuse e le directory delle chiavi
effimere sono state rimosse. Nessun percorso, hash o contenuto della chiave client e' persistito.

L'intervallo usa 20.000 repliche di bootstrap non parametrico gerarchico e stratificato: vengono
ricampionati prima i blocchi-chiave, poi le righe entro gli strati fissi `probe x ordine`,
preservandone la numerosita' e l'accoppiamento A29/A33. L'estimando e'
`100 * (1 - media_geometrica(A33/A29))`.

## Estensione automatica preregistrata

Il piano iniziale prevedeva tre blocchi, 60 coppie misurate e 12 warm-up. L'analisi iniziale ha
osservato una riduzione geometrica del 12,554%, CI 95% `[10,156%, 14,679%]`, con larghezza
**4,522 punti percentuali**. La differenza fra gli ordini A/B e B/A era soltanto 0,274 punti.

Il piano imponeva una sola estensione di altri tre blocchi se la larghezza del CI o la differenza
fra gli ordini superava 2 punti. L'estensione e' quindi scattata **soltanto** per
`bootstrap_ci95_width`; le 60 righe iniziali sono rimaste byte-identiche, come attestato dallo
stesso hash timing prima e dopo l'estensione
`7317a1138e748d80f1457d2cc736ac28511f8ac8851de12ba2306cecbb340b24`.

Dopo l'unica estensione consentita, il CI finale e' largo 3,789 punti, ancora oltre la soglia.
Questo non autorizza ulteriori campionamenti post hoc: documenta invece l'incertezza residua fra i
sei blocchi.

## Ordine, blocchi e deriva

| partizione | riduzione geometrica A33 | vittorie A33 |
|---|---:|---:|
| blocco 0, iniziale | 13,346% | 19/20 |
| blocco 1, iniziale | 12,233% | 18/20 |
| blocco 2, iniziale | 12,078% | 16/20 |
| blocco 3, estensione | 15,718% | 18/20 |
| blocco 4, estensione | 14,786% | 16/20 |
| blocco 5, estensione | 14,185% | 18/20 |
| ordine A29->A33 | 14,001% | 52/60 |
| ordine A33->A29 | 13,467% | 53/60 |
| prima meta' cronologica | 12,554% | 53/60 |
| seconda meta' cronologica | 14,898% | 52/60 |

La differenza fra gli ordini e' 0,535 punti percentuali. La differenza fra le due meta'
cronologiche e' invece 2,344 punti; le pendenze OLS delle latenze sono +19,139 ms/coppia per A29 e
+12,793 ms/coppia per A33, mentre la pendenza della riduzione e' +0,02462 punti/coppia. Il vantaggio
relativo compare in tutti e sei i blocchi, ma la deriva temporale e la variabilita' fra blocchi non
sono trascurabili.

## Provenienza e riproducibilita'

Invocazione eseguita (l'`argv` interno e' persistito nel JSON):

```bash
uv run --python 3.12 python benchmark/fhe_exact_id_paired_a29_a33.py \
  --run --timeout 900
```

| artefatto/input | SHA-256 |
|---|---|
| JSON finale | `659a996f5094112b3ea34ee3306a65bf03c8b308cd0d212c597890fc6fd71b8d` |
| CSV finale | `c61f99136912b667cc051f4d33dd2c3cb890ceb891eb26c6c70468684b460329` |
| harness paired | `cb41379d9f77601f321ff14c2deaf439f3b9b3fe0ec922a47feaa92d0e525910` |
| dipendenza validator | `b54fbc7ef278e53a08ad08eed4429833a7fba62b15ba810bc12c31af4904e79d` |
| binario congelato A29 | `cb0d0c1736713ae7b7a36450456a6ea45cab5bd8ac63d0c08c78220b4aaba102` |
| binario congelato A33 | `13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59` |
| patch sorgente A29 | `7858a3e51c50ddbd94ea76dbcc50410ffa37b10b99cad1eebb8609851b66cb54` |
| patch sorgente A33 | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| cache DigiFace | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| configurazione | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |

Il paired harness non interroga Git durante il run: dichiara autorevoli binari, patch e manifest
degli snapshot congelati. I README degli snapshot li legano al branch
`thesis-evidence-audit-2026-09`, base
`6611c185adc9a658a075519b4316386f0bb48656`, piu' gli input copiati dal worktree sporco. Tutti gli
input registrati risultano invariati prima/dopo. L'ambiente registrato e' macOS arm64, Python
3.12.11 e NumPy 1.26.4.

Artifact grezzi:

- [CSV](fhe_digiface_exact_paired_a29_a33_2026-09-02.csv)
- [JSON](fhe_digiface_exact_paired_a29_a33_2026-09-02.json)
- [harness paired](../fhe_exact_id_paired_a29_a33.py)
- [patch sorgente A29](../patches/a29_manylut_source_2026-09-02.patch)
- [patch sorgente A33](../patches/a33_aligned_sparse_source_2026-09-02.patch)

## Limiti

Il carico host era molto alto e non stazionario: load average 1/5/15 minuti
`78,478/209,616/237,987` prima e `57,918/49,983/54,955` dopo, su 16 CPU logiche. Le latenze
assolute non rappresentano una macchina idle. L'accoppiamento sugli stessi byte, il bilanciamento
dell'ordine, sei chiavi fresche e 105/120 vittorie rendono l'attribuzione relativa ad A33
persuasiva **in questo campione**, ma non eliminano il carico condiviso, l'esecuzione seriale entro
blocco o l'autocorrelazione non misurata. Il bootstrap tratta le righe entro strato/blocco come
scambiabili e non modella esplicitamente tale autocorrelazione.

Il benchmark copre cinque probe di frontiera fissi, una galleria DigiFace `N=127`, soglia uniforme
`T=4` e il fast path A33 allineato. Non stima l'accuratezza biometrica della popolazione, non prova
la correttezza per tutti gli input, non deriva una `p-fail` crittografica end-to-end e non sostiene
claim di novita'. Il CI e' un intervallo empirico condizionato al disegno e al carico di questo
run, non una garanzia universale di speedup.

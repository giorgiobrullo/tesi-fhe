# A62: A50 + A53 integrati sul parametro A44, evidenza FHE di componente

Data: 2 settembre 2026.

## Risultato

A62 materializza nello stesso core Rust i due risparmi necessari per raggiungere il conto
congelato A53:

```text
A44 / A41 / A38                      3655 BR / 3274 KS / 4206 marginali
A50: stati 0/1 + OR radix 15         3455 BR / 3074 KS / 4006 marginali
A53: scan group-4 + cifre base 15    3390 BR / 3009 KS / 3930 marginali
```

La sola sostituzione della scan avrebbe prodotto 3590 BR, non 3390. Per questo il precedente
piano A61 e' superato: il binario A62 contiene sia la riduzione A50 sia la scan A53.

Rispetto ad A44, il grafo N=127 rimuove 265 BR/PBS (-7,250%), 265 key switch classici
(-8,094%) e 276 output marginali conservativi (-6,562%). Questi sono risparmi strutturali; la
latenza deve essere misurata con un benchmark appaiato sullo stesso parametro e sugli stessi
ciphertext.

## Contratto exact-ID e wire

Il server restituisce due LWE p16 freschi a `Delta=2^59`:

```text
low  = code mod 15
high = floor(code / 15)
client: code = low + 15*high
```

`code=0` significa rifiuto; `code=i+1` identifica il primo argmin autorizzato. Non esiste una
somma cifrata terminale code56. Il parametro e' il preset TFHE-rs 0.11.3 Gaussian m1/c3
max-noise 15, fingerprint
`b0033dc6668c8b949f5139cb0dfdb5367e35dce285121666b8262fa73ad367d1`.

## Gate eseguiti

- audit statico indipendente: 8/8 test Python, 512 fixture clear, tutti i conteggi N=1..128;
- build release locked/offline riuscita;
- test Rust: 23 passati, zero fallimenti, tre diagnostiche FHE ignorate intenzionalmente;
- small FHE: 22/22 su una chiave fresca;
- focused FHE iniziale: 6/6 su una chiave fresca;
- focused FHE replicato: 18/18 su tre chiavi fresche;
- full FHE: 96/96, cioe' 32 fixture su ciascuna di tre chiavi fresche;
- totale osservato A62: **142/142 valutazioni su otto key-block dichiarati effimeri**.

Le fixture includono confine accept/reject, rifiuto globale, primo e secondo ID, tie-first, ID
60/64 e le due code massime 127/128. Per esempio, il codice 127 e' stato decifrato come
`low=7, high=8`, e 128 come `low=8, high=8`. I contatori runtime N=127 sono sempre
`3390/3009/3930`; N=128 usa `3415/3031/3959`.

Il gate fail-closed A69 rilegge i log senza eseguire crittografia, impone ordine/cardinalita' delle
fixture, binding del parametro, ricostruzione base-15, contatori, sommari e assenza di failure
marker. Il JSON canonico risultante ha SHA-256
`c72c22b4560093f437cce0029bef098556e27d6f1a4b520cc3180f221be5ce3a`.

## Tempi: cosa non si puo' ancora dire

Il full harness usa un probe nullo e gallerie artificiali minimali. Alcuni casi producono
ciphertext triviali e terminano in circa 0,04 s pur incrementando il contatore logico; i casi con
template nontriviali N=127/128 osservano invece circa 7,7--11,5 s sotto carico host variabile.
Questa distribuzione non e' una misura applicativa e non va confrontata con le mediane primarie
A38.

Inoltre l'adapter A53 iniziale esegue parti della scan sequenzialmente e rialloca accumulatori raw.
Serve prima una revisione latency-ready, poi un paired A44/A62 con ordine bilanciato e gli stessi
byte cifrati. Il rapporto dei conteggi non e' una promessa automatica di secondi.

## Limiti e stato

A62 e' ora **FHE-validato come componente**, non promosso:

- non e' ancora integrato nel servizio/Docker e non ha eseguito la primaria DigiFace da 632 query;
- non esiste ancora un paired A44/A62;
- il wire base-15 deve essere vincolato esplicitamente per non essere confuso col base-16 A44;
- le primitive raw custom non ereditano automaticamente il `NoiseLevel` delle API shortint
  checked; il bound end-to-end `p_fail` resta quindi non numerico;
- otto dichiarazioni `ephemeral` nei log non provano la cancellazione fisica della memoria.

Il riferimento checked A64 dimostra che raw/ManyLUT non sono necessari per ottenere la stessa
semantica con provenance del rumore, ma il suo ledger N=127 e' 2.434.997 possibili PBS, circa 620
volte i 3.930 marginali conservativi A62. E' un riferimento di correttezza/formalizzazione, non
ancora un'alternativa pratica.

## Artefatti congelati

| artefatto | SHA-256 |
|---|---|
| build | `8e5a4cb49edd20b2e30b7a106ec7496478264db917418e862481cb028540e1e3` |
| test libreria Rust | `c143b72a04ef35bb9eea039d39e41fdbe678ae8d308ef4f27348258762eff5d6` |
| test harness Rust | `326aace6a7ce27863dbd3494b022bb53bddada8ab93a7af05aba31feb5251261` |
| dry plan | `8b89e7b92e344eeedf1e00f4454bd9b7423ab0b384813968e5b1f5cc01fc1596` |
| small 22/22 | `84ad8ce3471f02e825c72fa400f9e51f0eabe8fd15e97ee0514a21a47ce02ee1` |
| focused 6/6 | `931d9d57a4f47dcdc1645b194700f0cc0d41d7f310ef5cd51e300ab52d2bd258` |
| focused 18/18 | `70450f0bcfa02f6f070bae0372b4c2c71392f04cab90aa56c00d92f067416dd6` |
| full 96/96 | `13b9e9e20b4f03d6931b963f0f3220ba091ce2d8c90e016f4803e0a09767688e` |
| gate JSON A69 | `c72c22b4560093f437cce0029bef098556e27d6f1a4b520cc3180f221be5ce3a` |
| binario release eseguito | `99095bdb884bfc9be0174d4f5e487987b07692ee8eb32d6c677d3a0726a80991` |

Sorgente isolato: `tmp/a62-a53-a44-integrated-prototype`. Validatore read-only:
`tmp/a69-a62-evidence-gate`.

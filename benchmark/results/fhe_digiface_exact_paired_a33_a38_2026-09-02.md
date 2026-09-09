# A33 vs A38: benchmark appaiato exact-ID

Data run: 2026-09-02T15:43:00Z--16:26:16Z. Durata wall: 2.595,956 s
(43 min 15,956 s).

## Esito

**PASS nel perimetro del confronto appaiato.** A38 conserva il contratto exact-ID e, nelle 120
coppie misurate, riduce la latenza server geometrica del **13,828%** rispetto ad A33
(`A38/A33 = 0,861718`, circa **1,160x**). L'intervallo bootstrap gerarchico al 95% osservato in
questo run e' **[11,729%, 15,806%]**.

| misura primaria | A33 | A38 | confronto appaiato |
|---|---:|---:|---:|
| PBS / blind rotation | 4.273 | 3.655 | -618 (-14,463%) |
| mediana server nel campione | 9.251,5 ms | 7.881,55 ms | - |
| media server nel campione | 9.543,138 ms | 8.227,141 ms | - |
| p95 server nel campione | 12.397,9 ms | 10.957,0 ms | - |
| delta appaiato mediano `A38-A33` | - | - | **-1.304,75 ms** |
| riduzione geometrica | - | - | **13,828%** |
| vittorie | 13/120 | **107/120** | 0 pareggi |

La riduzione strutturale dei PBS e quella temporale differiscono di 0,635 punti percentuali in
questo campione. La vicinanza e' coerente con le blind rotation come costo dominante, ma non prova
una legge lineare universale: A38 cambia anche KS, accessi, scheduling e struttura delle LUT.

## Accordo semantico exact-ID

Le 144 coppie totali (120 misurate e 24 warm-up esclusi) hanno tutte restituito lo stesso codice
con A33 e A38 e lo stesso codice dell'oracolo clear:

- `0` per i due probe oltre soglia;
- `i+1` per i tre probe sotto la soglia inclusiva, con l'indice del primo argmin;
- contratto `exact-open-set-id-v2` in entrambe le risposte;
- coppia PBS sempre `4.273/3.655` e galleria sempre `N=127`;
- **zero errori e zero discrepanze semantiche**.

Questo controlla l'intero output cifrato `0`/ID, non soltanto la decisione accept/reject. Le fixture
component A38 separate coprono tie interni, tie di coda e ID 127/128; i cinque probe fissati di
questo benchmark non sono una suite esaustiva del tie-breaking.

## Disegno appaiato

Il piano e' stato fissato prima del run:

- tre blocchi iniziali, ciascuno con una chiave fresca, quattro warm-up e 20 coppie misurate;
- cinque probe DigiFace di frontiera con minimi clear `2,3,4,5,7` e soglia uniforme inclusiva
  `T=4`;
- per ogni probe e blocco, due ordini A33->A38 e due ordini A38->A33;
- cifratura completata prima di avviare i due server del blocco;
- gli stessi byte del probe ciphertext inviati ad A33 e A38 dentro ogni coppia;
- ciphertext freschi fra coppie e decifratura rinviata fino alla fine delle misure del blocco;
- ordine di startup dei server alternato fra blocchi;
- tempo primario preso dall'header server `X-Tempo-Ms`; HTTP wall conservato come secondario.

Tutti i 144 ciphertext sono distinti fra coppie e byte-identici fra A33 e A38 dentro la rispettiva
coppia. I sei blocchi usano sei hash distinti della server key. Le directory con chiavi effimere
sono state rimosse, i processi server terminati e le porte chiuse. Nessuna chiave client o relativo
hash e' registrato nell'artifact.

L'intervallo ricampiona prima i blocchi-chiave, poi le righe dentro gli strati fissati
probe-per-ordine, preservandone la numerosita'. L'estimando e'
`100 * (1 - media_geometrica(A38/A33))`; il bootstrap usa 20.000 repliche e seed `20260902`.

## Estensione preregistrata

Dopo i primi tre blocchi e 60 coppie, la riduzione era 14,355% con CI 95%
`[12,015%, 16,879%]`. La larghezza di **4,865 punti** superava la soglia preregistrata di 2 punti;
la differenza fra gli ordini era invece 1,406 punti, sotto la propria soglia di 2.

E' quindi scattata l'unica estensione permessa, altri tre blocchi e 60 coppie. Le righe iniziali
sono rimaste byte-identiche: l'hash dei loro campi temporali e'
`ae2084ac9299c264d52361b409f89cc60b27421d214d14aaac93d605ea5af488` sia prima sia dopo
l'estensione.

Il CI finale resta largo **4,076 punti**, ancora oltre l'obiettivo. Non sono stati aggiunti altri
campioni post hoc: il disegno consentiva al massimo uno stage aggiuntivo. L'intervallo finale
documenta quindi l'incertezza residua fra sei blocchi, non una soglia di precisione raggiunta.

## Ordine, blocchi e deriva

| partizione | riduzione geometrica A38 | vittorie A38 |
|---|---:|---:|
| blocco 0, iniziale | 14,799% | 19/20 |
| blocco 1, iniziale | 15,023% | 17/20 |
| blocco 2, iniziale | 13,233% | 19/20 |
| blocco 3, estensione | 15,726% | 19/20 |
| blocco 4, estensione | 13,555% | 17/20 |
| blocco 5, estensione | 10,535% | 16/20 |
| ordine A33->A38 | 13,159% | 52/60 |
| ordine A38->A33 | 14,492% | 55/60 |
| prima meta' cronologica | 14,355% | 55/60 |
| seconda meta' cronologica | 13,298% | 52/60 |

Il vantaggio compare in tutti e sei i blocchi e per tutti e cinque i probe. La differenza fra gli
ordini e' 1,332 punti; quella fra le due meta' cronologiche e' 1,057 punti. La pendenza OLS della
riduzione e' `-0,02484` punti per coppia; le pendenze delle latenze sono `+5,184 ms/coppia` per A33
e `+7,706 ms/coppia` per A38. Queste diagnostiche mostrano variabilita' e deriva, ma non cancellano
la separazione osservata in ogni blocco.

| probe | minimo clear | riduzione geometrica A38 | vittorie A38 |
|---:|---:|---:|---:|
| 265 | 2 | 15,624% | 21/24 |
| 758 | 3 | 13,256% | 22/24 |
| 211 | 4 | 11,221% | 19/24 |
| 1943 | 5 | 14,817% | 23/24 |
| 407 | 7 | 14,158% | 22/24 |

## Provenienza e riproducibilita'

Invocazione:

```bash
uv run python benchmark/fhe_exact_id_paired_a33_a38.py --run
```

| artefatto/input | SHA-256 |
|---|---|
| JSON finale | `003ae3ec413c5788a689f63c79d97b1141f641752846f09e131a2eba1a0cb808` |
| CSV finale | `d8dd128e2eaf8f5a13c302220a1113bdc509f182da0e67c5ba903cc5357979e6` |
| harness paired | `ea14a7d07f079418910c6a21dababd3d1c918d9f06554edf7eb492494c10755e` |
| test harness | `1d12d230357ea5c71c0cfb0aa586926e54e6545068fd77a8cec14a8930658661` |
| binario congelato A33 | `13a1593be85d8e585bdf48d7d4e8a09a57a82902f6e8da7299a5b02415a3ea59` |
| binario congelato A38 | `f4cdc28f92ffae8d34c207a06896299015aca2673fce14a959cc3bea34dc1e02` |
| patch sorgente A33 | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| core integrato A38 | `5230f3863a5cad726aefe51a3c6a786899e4f1cdd47aeb0ff8f7141fcc3917ae` |
| validator condiviso | `07a79bf92e409d67af3fcc003847eb28dba9041e753babca19ec66711053c559` |
| cache DigiFace | `1b5eab3a9586715583f084afebcbeb417025210d2623ce3f9b35f0c196095e99` |
| configurazione | `eef0f46e153a6c3f23e8fb258a34db663376a391578aff03a79046e4691318dc` |

Il run non interroga lo stato Git mutabile: usa binari, patch, snapshot e manifest congelati. Tutti
gli input registrati risultano invariati prima e dopo. Il JSON e' pubblicato atomicamente senza
sovrascrivere file preesistenti; il suo hash e' calcolato esternamente perche' un file non puo'
contenere il proprio SHA-256.

Artifact:

- [CSV](fhe_digiface_exact_paired_a33_a38_2026-09-02.csv)
- [JSON](fhe_digiface_exact_paired_a33_a38_2026-09-02.json)
- [harness](../fhe_exact_id_paired_a33_a38.py)
- [suite primaria A38](fhe_digiface_exact_primary_a38_2026-09-02.md)
- [component FHE A38](../../experiments/14_pipeline_tfhe_rs/results/exact_id_a38_combined_component_fhe_2026-09-02.md)

## Limiti

Il carico host era alto e non stazionario: load average 1/5/15 minuti
`10,894/13,651/57,428` prima e `164,300/189,440/144,706` dopo, su 16 CPU logiche. Le mediane
assolute non sono una baseline idle e il paired non elimina tutta la contesa condivisa, la deriva
o l'esecuzione seriale dentro ogni coppia. Bilanciamento degli ordini, sei chiavi, vantaggio in
ogni blocco e 107/120 vittorie rendono persuasiva l'attribuzione relativa ad A38 **in questo
campione**, non universale.

I 120 pair ripetono cinque probe di frontiera: stimano la latenza di implementazione, non sono 120
campioni biometrici indipendenti. Il run non sostituisce la suite primaria da 632 query, non stima
DIR/FPIR della popolazione, non prova il `p-fail` crittografico composto, non valida Docker e non
copre il fallback A29 per soglie arbitrarie. Non sostiene claim di novita' o priorita' scientifica.

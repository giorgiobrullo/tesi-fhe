# A33: contabilita' condizionale della probabilita' di failure

Data: 2026-09-02. Configurazione: A33 aligned-sparse, galleria uniforme `N=127`, TFHE-rs 0.11.3,
parametro `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64`.

## Esito

Questo rapporto fornisce il **conteggio deterministico** degli eventi, ma non fornisce un
certificato numerico end-to-end.

| quantita' | valore |
|---|---:|
| blind rotation/PBS | 4.273 |
| key switch strutturali | 3.892 |
| rotazioni multi-output | 635 |
| marginali di output conservative | 4.908 |
| `log2(p_fail)` nominale del parametro | -71,625 |
| union bound condizionale sui 4.273 eventi BR | `log2 <= -59,563966` |
| union bound condizionale sulle 4.908 marginali | `log2 <= -59,364080` |
| failure del decode finale non bootstrappato | **non valutata** |
| bound numerico end-to-end | **assente** |

La somma di Boole non richiede indipendenza fra gli eventi. Le due uscite di una rotazione
multi-output condividono pero' la stessa blind rotation: il conteggio BR le tratta come un evento,
mentre quello conservativo delle marginali aggiunge l'uscita extra senza dichiararla indipendente.
I key switch non vengono sommati nuovamente come trial separati, perche' il loro rumore alimenta il
PBS successivo nel percorso KS-to-PBS.

## Formula condizionale corretta

Sia `A` l'insieme di assunzioni: client onesto e bounded, template e dominio validi, chiavi generate
e abbinate correttamente, server onesto, software/hardware/trasporto corretti. L'unica forma
attualmente giustificata e':

```text
P(output errato | A)
  <= sum_i P(F_i | A, prefisso corretto)
     + P(decode finale errato | A, tutti i BR/PBS corretti).
```

Applicare meccanicamente `4.273 * 2^-71,625` produce circa `2^-59,564`, ma resta condizionato al
fatto non ancora provato che il valore nominale si applichi a ogni ingresso PBS custom
raggiungibile. Usare le 4.908 marginali produce il conto ancora piu' conservativo
`2^-59,364`. Nessuno dei due include il secondo termine.

## Perche' manca il termine finale

Il codice `0/ID` e' una somma lineare finale a `Delta=2^56`, senza PBS conclusivo. Il valore
`p_fail` pubblicato nel parametro TFHE-rs riguarda la configurazione delle primitive supportate e
non fornisce da solo la coda di decrittazione di questa somma custom. Servono almeno:

1. un bound della varianza/coda per ogni ingresso PBS raggiungibile, compreso il primo stadio dopo
   encryption e scoring GLWE/clear;
2. una giustificazione per entrambe le uscite correlate delle rotazioni multi-output;
3. propagazione della covarianza o un bound sicuro per le somme lineari che portano alle radici ID;
4. un bound esplicito del decode dell'unico LWE finale a `Delta=2^56`.

Finche' questi obblighi restano aperti, scrivere `p_fail A33 = 2^-59,56` sarebbe un overclaim.

## Evidenza empirica separata

La suite primaria A33 osserva 0 output errati su 632 query, 131/131 autorizzazioni e 632 ciphertext
probe distinti. Se, solo a fini descrittivi, si modellano le query come Bernoulli iid, il limite
superiore unilaterale al 95% e' `0,004728866`. Questo numero non e' un bound crittografico: un
campione di 632 query non puo' risolvere una probabilita' dell'ordine di `2^-60`.

## Dati e limite della rigenerazione

Il [generatore del conteggio](../a33_pfail_accounting.py) è incluso, ma verifica
anche una trascrizione diagnostica A33 non distribuita e una specifica copia
dei sorgenti TFHE-rs. Il clone non contiene quindi tutti gli input necessari
a rigenerare il certificato storico. Le formule e i conteggi sono riportati
sopra; il JSON seguente documenta il risultato calcolato.

| artefatto | SHA-256 |
|---|---|
| JSON deterministico | `d76bd4cb9337523d0b997ad6ed942a03b4345a04a376a5378ee79792430af896` |
| generatore | `4b32a4da363e4a2562b42a04f03b462eda98be0926dc3236c5d33acd675ac785` |
| patch A33 | `6d07077efc52e721399740ef7d443ca87ee0a6c575cd19b7a453d5109224f7f5` |
| core A33 estratto dalla patch | `1d50a2b0e6f98069e0ab2de0eb228133543b5792cf0b34016031593de1e0850d` |
| JSON suite primaria | `51be273a6a81274b1314f56af3a0ae62328131f035a7bff236d01b70751f9c49` |
| CSV suite primaria | `0d35640d7803969f4fb4781bac3975e367e477447ecbf6ffc9fb6a090669a011` |

La generazione e' stata provata su Python 3.9 e 3.12 e il replay in un file temporaneo ha prodotto
gli stessi byte. Il JSON grezzo resta l'artefatto autorevole:
[exact_id_a33_pfail_accounting_2026-09-02.json](exact_id_a33_pfail_accounting_2026-09-02.json).

Gli hash dei JSON si riferiscono agli estratti pubblicati; la
[corrispondenza con gli originali](../../docs/provenienza-dati.json) conserva entrambe le impronte.

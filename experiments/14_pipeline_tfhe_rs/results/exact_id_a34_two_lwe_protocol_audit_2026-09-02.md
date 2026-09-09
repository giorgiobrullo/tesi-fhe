# A34 exact-ID: audit statico del protocollo a due LWE nibble

Data: 2026-09-02. Stato: **modello clear e proiezione strutturale, non implementato e non
validato in FHE**. Questo audit non modifica il core Rust, il servizio, il formato wire vivo, le
chiavi o gli snapshot congelati.

## Esito

La variante e' semanticamente adatta all'identificazione esatta: il server restituisce due LWE
che cifrano

\[
(lo, hi) = (code \bmod 16, \lfloor code/16\rfloor),
\qquad code = lo + 16hi,
\]

dove `code=0` significa rifiuto e `code=i+1` identifica l'iscritto `i`. Per `N<=128` la mappa fra
`code` e la coppia e' biunivoca: il rifiuto e' `(0,0)`, l'ID massimo 128 e' `(0,8)`. Quindi il
client apprende lo stesso rifiuto/ID preciso del contratto a un solo codice, non un'informazione
semantica aggiuntiva.

Il vantaggio ingegneristico e' reale ma circoscritto: i due digit escono direttamente a
`Delta=2^59`, senza pesare l'high nibble, senza sommare ciphertext e senza riportare il risultato
alla scala stretta `Delta=2^56`. Questo elimina **la specifica somma finale non rinfrescata** che
nel conto A29/A33 aveva un termine di decode non valorizzato. Non basta ancora a dichiarare una
p-fail end-to-end: rimane da dimostrare che il valore nominale del parameter set si trasferisca
alle PBS custom e a tutti i loro ingressi raggiungibili.

## Circuito e conteggi

La modifica di protocollo parte dal modello A34 two-nibble gia' separato. Il selector di ciascun
gruppo emette `lo` e `hi` come due marginali a scala p16; due alberi radix-4 one-hot terminano in
due p16 identity PBS. La risposta prende direttamente le loro due LWE. Cambiano i coefficienti
terminali e il contratto wire, non la topologia.

Per `N=127`:

| perimetro | BR/PBS | KS | marginali LWE |
|---|---:|---:|---:|
| solo scan/output two-nibble | 210 | 210 | 253 |
| whole projection con pre-scan A33 | 4.111 | 3.730 | 4.789 |
| A33 vivo di riferimento | 4.273 | 3.892 | 4.908 |
| risparmio proiettato rispetto ad A33 | 162 | 162 | 119 |

Le 253 marginali dello stage contano due sample extraction per i 43 selector dual-output. Le due
uscite finali sono gia' comprese nelle 4.789 marginali whole: aggiungerle di nuovo al conto della
union bound sarebbe un doppio conteggio.

La proiezione indipendente che combina anche il candidato A34 top-category resta quella gia'
modellata altrove, `3.982 BR / 3.601 KS / 4.533 marginali`; non e' necessaria per questo cambio di
protocollo e non e' stata validata in FHE. Il presente audit usa come base primaria il piu'
conservativo pre-scan A33 (`4.111/3.730/4.789`).

## Scala e decode

Ogni digit usa i 16 slot indipendenti del modulus totale p16 a `Delta=2^59`. La distanza fra slot
adiacenti e' `2^59` e il raggio di rounding e' `2^58`. Il codice corrente a `Delta=2^56` ha raggio
`2^55`: il margine assoluto terminale cresce di 8 volte. Questo confronto geometrico non implica
da solo una riduzione della probabilita' di errore di 8 volte, perche' serve anche la distribuzione
del rumore effettivo.

Il decoder proposto:

1. decifra e arrotonda separatamente entrambe le LWE come digit `0..15`, gestendo il rumore
   negativo attorno allo zero sul toro;
2. calcola in chiaro `code=lo+16*hi`;
3. fallisce se un digit non e' canonico o se `code>N`;
4. restituisce rifiuto per zero, altrimenti indice `code-1`.

Il range check e' utile ma non e' un codice di rilevazione degli errori. Per esempio, con `N=128`
un errore che porta il low nibble del codice 1 dalla cella 1 alla cella 2 produce la coppia valida
`(2,0)` e quindi un ID errato, non un errore di formato. Autenticita', ridondanza e comportamento
contro un server malevolo non sono inclusi in questa variante.

## Dimensione della risposta

La proiezione mantiene il container raw-u64 corrente: una word che dichiara la lunghezza
dell'header, otto word di header e LWE da 2.049 word ciascuna. Un nuovo `output_mode` deve fissare
in modo non ambiguo la presenza di esattamente due LWE, cosi' non serve una nona word di count.

| risposta grezza | formula | byte |
|---|---:|---:|
| contratto vivo, una LWE | `8 * (1 + 8 + 2049)` | 16.464 |
| proposta, due LWE | `8 * (1 + 8 + 2*2049)` | 32.856 |
| incremento | una LWE payload | 16.392 |

La proposta e' `1,9956268x` la risposta corrente, appena meno del doppio perche' prefix e header
restano condivisi. Sono byte del body cifrato grezzo, non includono framing HTTP/TCP o eventuale
base64. Il valore 32.856 e' una proiezione del formato, non una misura di un servizio gia'
implementato.

## Cosa succede alla p-fail finale

Il parameter set congelato dichiara `log2_p_fail=-71.625`, quindi il valore nominale per evento e'

\[
p=2^{-71.625}=2,74616457523\cdot 10^{-22}.
\]

Se si dimostra che ciascuna delle due uscite terminali ha, condizionatamente al prefisso corretto,
probabilita' di lasciare la propria cella di decode al piu' `p`, allora senza alcuna ipotesi di
indipendenza:

\[
P(F_{lo}\cup F_{hi}) \le 2p
=5,49232915046\cdot10^{-22}=2^{-70.625}.
\]

Nel conto whole conservativo, sempre **solo condizionalmente** alla validita' dello stesso limite
per tutte le marginali:

\[
4789p=1,31513821508\cdot10^{-18}=2^{-59.3994913}.
\]

Per completezza, lo stesso calcolo ipotetico vale `253p=6,94779637533e-20`,
`log2=-63,6420064`, per le sole marginali dello stage e
`4111p=1,12894825688e-18`, `log2=-59,6197263`, se si conta una failure-event per BR whole invece
di una per marginale. I 3.730 KS restano conteggi strutturali: non vengono sommati come eventi
indipendenti, perche' il loro rumore deve essere coperto all'ingresso della PBS successiva.

Non va sommato un ulteriore termine per la vecchia somma finale: il decode delle due LWE e'
assorbito nei due eventi terminali se l'evento PBS comprende l'intera uscita, la decifratura e il
rounding nella cella p16. Questa e' la chiusura strutturale del termine, non ancora la prova delle
sue premesse.

Per `N=127` i terminali sono due blind rotation p16 identity distinte. Non vengono dichiarate
statisticamente indipendenti: condividono input, DAG, BSK e KSK, e la union bound non ne ha bisogno.
Per le gallerie `N<=3`, invece, non esiste un livello di riduzione e i due terminali sono sample
extraction correlate della stessa rotazione selector; anche questo caso richiede un bound
marginale o comune esplicito.

## Obblighi ancora aperti

Prima di scrivere una garanzia end-to-end servono almeno:

1. il trasferimento giustificato di `log2_p_fail=-71.625` dal parametro shortint alle chiamate
   `core_crypto` custom, incluse le marginali estratte dalla stessa rotazione;
2. la propagazione di rumore iniziale, score lane, KS e somme con fan-in limitato fino a ogni
   ingresso PBS raggiungibile, sotto condizionamento sul prefisso corretto;
3. un audit Rust isolato dei coefficienti degli accumulatori, delle scale e dei gradi di sample
   extraction per le due uscite, senza aritmetica dopo le PBS terminali;
4. una validazione FHE del formato a due LWE e dei boundary, che resterebbe evidenza empirica e non
   potrebbe misurare direttamente una coda nominale di ordine `10^-22` per evento;
5. se interessa un avversario attivo, un contratto separato per integrita'/autenticita': due digit
   e un controllo di range non autenticano la risposta.

Di conseguenza lo stato corretto e': **la variante rimuove il collo di bottiglia analitico della
somma finale a Delta=2^56, ma il bound end-to-end rimane condizionale e numericamente non
certificato**.

## Leakage

Al plaintext, `(lo,hi)` e `code` inducono la stessa partizione degli esiti: rifiuto oppure uno
specifico ID. Al server/transcript la variante e' distinguibile per mode e lunghezza pubblici, ma
la lunghezza e' fissa e non dipende dall'esito. Affermare che le due LWE non rivelino altro richiede
la normale sicurezza composizionale multi-ciphertext dello schema e non equivale a una prova di
circuit privacy; quest'ultima non viene rivendicata. In particolare il client riceve due campioni
di rumore valutati invece di uno: la biiezione dei plaintext non prova che la distribuzione dei
ciphertext nasconda ogni dettaglio del circuito. Se il threat model include un client malevolo che
analizza tali distribuzioni, servono un audit di circuit privacy ed eventualmente tecniche di
rerandomizzazione/noise flooding separate.

## Evidenza riproducibile

Modello:

```text
benchmark/a34_two_lwe_protocol_model.py
```

Test:

```text
python3 -m unittest tests.test_a34_two_lwe_protocol_model
python3 benchmark/a34_two_lwe_protocol_model.py --gallery-size 127
```

La validazione deterministica copre tutte le gallerie `N=1..128`, tutti i rifiuti, ogni vincitore
singleton, ogni suffisso di tie con semantica first, tutti i 129 codici e gli estremi interni delle
16 celle di rounding. Non esegue Cargo, keygen o FHE.

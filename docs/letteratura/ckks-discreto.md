# CKKS numerico, CKKS discreto e conversioni di schema

[Indice della rassegna](../../letteratura.md) · [Primitive TFHE](primitive-e-codesign.md) · [Fonti](fonti.md)

Fonti verificate il **19 settembre 2026**; raccordo aggiornato il 22 settembre.
Il runtime mantenuto usa Head/PFKS con selettore corretto, anchor e pack4.
Questa scheda descrive alternative scientifiche, senza attribuirne le
funzionalità o i tempi al servizio locale. Il [confronto numerico del 20 settembre](../../output/figures/ckks-tfhe/selettore-corretto-20260920/LEGGIMI.md)
valuta due circuiti specifici, distinti da queste alternative.

## La funzione desiderata va distinta dalla rappresentazione

Il contratto della tesi sceglie il primo minimo dei punteggi interi ammessi,
applica la soglia inclusiva del vincitore e restituisce 0 oppure l'identità.
“Esatto” riguarda questa funzione sugli interi quantizzati. Non significa
identico al nearest neighbor degli embedding reali prima della quantizzazione,
né assenza di probabilità di errore crittografico.

Una descrizione generale di CKKS come limitato ai confronti approssimati è
incompleta. Occorre distinguere tre costruzioni:

| Costruzione | Rappresentazione e confronto | Condizioni da verificare per 0/ID |
|---|---|---|
| CKKS numerico | Score approssimati e comparatori polinomiali | Errore dello score, separazione dei valori, trattamento dell'uguaglianza, margine dalla soglia e decodifica finale |
| CKKS discreto | Interi o bit in un encoding discreto, con procedure di ripristino e bootstrap dedicate | Dominio, bound d'errore, carry, pulizia del rumore, convenzione di pareggio e composizione fino all'ID |
| CKKS↔FHEW/TFHE | Score impacchettati e passaggi a primitive discrete per operazioni non lineari | Scale, moduli, conversioni, margini del confronto, costo delle chiavi e formato dell'uscita |

Anche un calcolo numerico può produrre una decisione discreta corretta quando
i margini sono dimostrati. Viceversa, un selettore discreto può essere esatto
sui punteggi ridotti e cambiare il vincitore rispetto agli score originari.
Per confrontare due sistemi servono lo stesso oracolo e le stesse condizioni
sui pareggi e sulle soglie.

## Dai comparatori numerici ai dati discreti

**Confronto polinomiale.** Cheon, Dongwoo Kim e Duhyeong Kim,
[Efficient Homomorphic Comparison Methods with Optimal Complexity](https://eprint.iacr.org/2019/1234),
ASIACRYPT 2020, dimostrano complessità asintotica ottima per composizioni
polinomiali, imponendo una separazione `|a-b|≥ε`. Lee, Lee, No e Kim,
[Minimax Approximation of Sign Function by Composite Polynomial for Homomorphic Comparison](https://eprint.iacr.org/2020/834),
ePrint 2020/834 rivisto il 5 aprile 2021, ottimizzano le composizioni minimax
per costo e profondità. Il secondo lavoro non è l'origine dell'ottimalità
asintotica del primo. Aumentare il grado non risolve da solo il caso di
uguaglianza né dimostra la correttezza di un argmin composto.

**Bootstrap di piccoli interi.** Youngjin Bae, Jaehyung Kim, Damien Stehlé
ed Elias Suvanto, *Bootstrapping Small Integers With CKKS*, ASIACRYPT 2024,
propongono `SI-BTS`, che valuta funzioni su piccoli interi durante il bootstrap,
e un uso in batch su ciphertext DM/CGGI.
L'[ePrint 2024/1637](https://eprint.iacr.org/2024/1637), ricevuto l'11 ottobre
2024, descrive esplicitamente questa funzionalità. È una famiglia pertinente a
estrazione e LUT in batch; il costo ammortizzato su migliaia di valori non
è il tempo di risposta di una singola query con galleria piccola.

**LUT generali.** Andreea Alexandru, Andrey Kim e Yuriy Polyakov,
[General Functional Bootstrapping using CKKS](https://eprint.iacr.org/2024/1623),
CRYPTO 2025, ePrint 2024/1623 rivisto il 29 maggio 2025, costruiscono LUT
generali tramite interpolazione trigonometrica con controllo del rumore.
Il suffisso 1623 non va confuso con Tetris **2025/1623**. Anche qui i vantaggi
di throughput riportati appartengono ai domini, ai batch e ai parametri
degli autori; non misurano il percorso biometrico 0/ID.

**Aritmetica radix.** Jaehyung Kim,
[Efficient Homomorphic Integer Computer from CKKS](https://eprint.iacr.org/2025/066),
TCHES 2025, ePrint 2025/066 rivisto il 16 luglio 2025, rappresenta interi
unsigned come vettori di chunk e costruisce operazioni mediante CKKS discreto.
Il successivo [Faster Homomorphic Integer Computer](https://eprint.iacr.org/2025/1440),
TCHES 2026, ePrint 2025/1440 rivisto il 3 aprile 2026, riduce la latenza
dell'aritmetica radix; il [codice degli autori](https://github.com/jaehyungkim0/Faster-Computer)
è pubblico. La moltiplicazione intera è una misura di primitiva, distinta da
ranking o selezione con soglia.

**RadixCKKS.** Gyeongwon Cha, Dongjin Park e Joon-Woo Lee,
[Improved Radix-based Approximate Homomorphic Encryption for Large Integers via Lightweight Bootstrapped Digit Carry](https://eprint.iacr.org/2025/1740),
EUROCRYPT 2026, ePrint 2025/1740, ultima revisione 27 febbraio 2026,
propongono un ripristino della rappresentazione univoca tramite digit carry
che rende possibili operazioni non aritmetiche come il confronto. È un
precedente contro una presunta impossibilità generale del confronto in CKKS.
La fonte non fornisce automaticamente il tie-break, il payload ID e la
soglia del vincitore richiesti da questa tesi.

## Scheme switching: una baseline implementabile da qualificare

La documentazione ufficiale OpenFHE espone
[`EvalMinSchemeSwitching`](https://openfhe-development.readthedocs.io/en/latest/api/classlbcrypto_1_1SWITCHCKKSRNS.html)
per minimo e argmin dei valori impacchettati in CKKS, attraverso conversioni
ripetute a FHEW e ritorno. L'[esempio ufficiale](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/scheme-switching.cpp)
restituisce valore e argomento, come indicatore o indice secondo la
configurazione. Le API documentano vincoli su scale, moduli, slot e numero
di valori. L'esistenza del codice pubblico è evidenza di una funzionalità,
non di un confronto eseguito in questo repository.

Una [risposta dell'autrice sul forum OpenFHE](https://openfhe.discourse.group/t/evaluating-signs-of-vector-elements/1247)
del 6 maggio 2024 segnala che l'argmin via scheme switching non garantiva
la prima occorrenza nei pareggi. Il dato è storico: il comportamento di una
release scelta va verificato sul suo codice. Servono inoltre una soglia
applicata al solo vincitore e una decodifica 0/ID qualificata, includendo
tutti i passaggi di formato nel costo.

L'[esperimento CKKS locale](../../experiments/23_ckks_ottimizzazioni/README.md)
misura altre ottimizzazioni del percorso numerico. Non è un'implementazione
di questi lavori e non chiude il confronto con CKKS discreto. Le alternative
restano ammissibili senza che la loro presenza obblighi a cambiare il core
TFHE prima di avere un adattatore e un confronto coerente.

## Versioni e portata della verifica

I PDF completi dei cinque lavori su CKKS discreto sono ora disponibili.
La [lettura mirata dei testi](testi-integrali/ckks.md) identifica versioni,
pagine, algoritmi, condizioni d'errore e assetti sperimentali; comprende
anche Lee et al. e l'edizione pubblicata USENIX di Mazzone et al.
Supera il precedente limite di sola lettura di abstract e metadati.

Le tabelle verificano **8,85 ms/slot** per la moltiplicazione di Kim 2025/066
su un batch da 145 s, e **0,722 ms** per la LUT 8 bit di Alexandru su un
batch da 47,322 s. Faster Integer Computer usa riduzione lazy nel confronto
sperimentale: la canonicalizzazione aggiunge lavoro. Anche RadixCKKS separa
i tempi lazy da quelli exact. Prima di confrontare i tempi bisogna fissare
l'interfaccia richiesta dal consumatore e l'occupazione del batch.

Questa lettura non è una certificazione completa delle dimostrazioni né
una replica delle implementazioni. Le condizioni teoriche, le approssimazioni
del modello e gli errori empirici sono distinti nelle schede. I riferimenti
`main/latest` di OpenFHE rimangono mobili: una futura replica richiede
versione e commit fissati. La [bibliografia](aggiornamento-20260919.bib)
registra le versioni effettivamente consultate.

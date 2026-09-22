# Core Python storico

Questa cartella contiene le utility Python/Concrete condivise dagli esperimenti
iniziali e dai benchmark. Il percorso iniziale trasforma una foto in un
vettore numerico, lo converte in interi piccoli (quantizzazione), lo cifra
e calcola i punteggi rispetto alla galleria.

| File | Ruolo |
|---|---|
| [client.py](client.py) | Prepara e cifra la richiesta; nel prototipo iniziale decifra tutti i punteggi e sceglie il minimo. |
| [server.py](server.py), [matching.py](matching.py) | Preparano ed eseguono i circuiti Concrete dei punteggi; `matching.py` contiene anche le varianti con minimo e soglia cifrati. |
| [quantize.py](quantize.py) | Stima la scala sulla galleria e la riusa per convertire i vettori in interi. |
| [dataset.py](dataset.py), [metriche.py](metriche.py) | Preparano i dati e valutano il riconoscimento in chiaro. |

Il passaggio dal client che legge tutti i punteggi al circuito che produce
solo la decisione è descritto nell'[esperimento 06](../experiments/06_argmin_soglia/README.md).

Il core exact-ID più recente usa Rust e TFHE-rs. Si trova nel
[runtime mantenuto](../runtime/README.md), con la
[libreria](../runtime/core/src/lib.rs) e il servizio
che ne preserva il contratto di runtime. Non è un sostituto diretto delle API
Python di questa cartella. Gli snapshot Rust negli esperimenti 17–26 servono
a conservare le versioni realmente confrontate.

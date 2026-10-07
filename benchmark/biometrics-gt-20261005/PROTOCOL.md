# Trasferimento Georgia Tech nella galleria120

Preregistrazione 2026-10-05T10:49:22.727906+00:00, prima di decoder/detector/embedding/score sul dataset appena acquisito. Dataset fonteprimaria AraNefian,50identità/15JPEG ciascuna, archivioSHA2c4e379ef7c3cc5580eb409673a1e6eb75c5e5a7efd9bf3beb1de8059e835cbf. Mai usato localmente secondo i consumatori censiti; non certificare assenza dal pretraining o equivalenza delle sessioni.

Seed unico `varco-gt-transfer-20261005-v1`; ordinare identità e foto con SHA256 del seed/tag/nome. Prime20identità registrate, altre30sconosciute. Tre foto d'iscrizione per ognuno dei20, una query primaria, tre altre foto fuse come secondaria. Foto disgiunte; nessun reroll o sostituzione dopo estrazione.

Galleria: prime100voci nell'ordine congelato del catalogo della demo, ognuna col suo ritratto originale letto come preset del server; poi20nuoveidentitàGT.120voci totali,20nuoviiscritti, non120nuovepersone. La preparazione delle nuove iscrizioni e query usa la funzione originale `readPhotos` in Chrome headless (maxlato1280/JPEG0.9), poi decoder/allineamento/fusione/quantizzazione di produzione. Preset100 resta nel suo percorso reale, non passa nel codec dell'upload.

Congelare prima dell'inferenza manifestimmagini/ruoli, source/pesi/ambiente, codice del runner e codec. ResNet100/glintr100, detectorbuffalo_s160x160/soglia0.5, CPU4intra/1inter, scala0.04098006/qmax3, T273 inclusiva. Nessuna ritaratura o scelta di modello. Usare decoderPillow12.3 locale verificato senza mutarevenv.

Se non si forma una galleria120ammissibile, fermarsi prima delle query e conservare setupfailure. Nessuna sostituzione. Per ogni query contare decoder/no-face/nonfinite/domain failures, frame parziali, accettazione corretta, IDerrato accettato, rifiuto, falsoaccesso unknown. Regola: primo minscoreoriginale, poi soglia del solo vincitore; compareoracoloscalare con validate_input.

Primaria:50ricerche(20note/30unknown). Secondaria:50ricerche sulle stesse persone con altre foto, non100persone indipendenti e non testwebcam. FPIR su unknownammissibili; falseaccess/tentativi separato. CI ClopperPearson95% percondizione sotto esplicita ipotesi binomiale perpersona/galleriafissa. Con30unknown anche0falseaccessi noncertifica1%; risultato può essere negativo o nonconclusivo senza cambiare ilprotocollo. Nessun claim di popolazione1%, nessun confronto causale isolato sul numero difoto.

Questo primo run è biometricoinchiaro, non p_failFHE o nuova misuralatenza. Eventualeconcordanza FHE successiva richiede propriosource/review/guard/freshRAMkeys, senza leggere vecchikey/ciphertext. Tutto locale, noHTTPremoto/upload/Git o interventi suprocessiesistenti.

## Precisazioni prima del freeze

CI dichiarato: limite Clopper-Pearson unilaterale95% per la FPIR condizionata, non intervallo bilaterale. I due gruppi di foto usano le stesse30persone; nessun pooling in60unknown.

Mappa ID: preset1–100 nell'ordine del catalogo; GT101–120 nell'ordine hash delle prime20identità. Manifest esplicita tale ordine e T273 per ogni voce. GT unknown è disgiunto dalle20GT iscritte per etichetta del dataset. La sovrapposizione semantica con i100preset e con il pretraining non è verificata: i falsi accessi aggregati sono condizionati a questa ipotesi, e si separano accettazioni verso preset e verso altriGT.

Frame: fondere tutti e soltanto i frame con volto rilevato se almeno uno riesce; zero rilevati è fallimento. Un errore di decoder blocca l'intero tentativo, senza sostituire la foto. Conservare numero tentato/rilevato e tutti i fallimenti nei denominatori di tentativi.

## Revisione pre-esecuzione2

Prima revisione/sourcefreeze preservati nella cartella biometrics, nessun codec/inferenza eseguito. In v2 si rendono espliciti i fallimenti di shape/nonfinite e si controllano gli embedding float prima della quantizzazione senza cambiare i valori finiti. Il codec ha RPC limitate e attende l'uscita del solo Chrome appena creato; fallbackTERM/KILL può riguardare esclusivamente l'oggetto child appena lanciato. Nessun processo preesistente o PID salvato viene controllato. Nessun dato/outcome è stato consultato per queste correzioni.

## Revisione pre-esecuzione3

V2 preparata ma mai eseguita, preservata separatamente. V3 completa i tre rilievi della review iniziale: serve lo stesso buffer shared.js verificato, controlla la shape float prima della quantizzazione e registra la fase decoder/allineamento/embedding dei fallimenti. Stessi ruoli, immagini, seed, pesi e aritmetica valida; nessun outcome letto.

## Revisione pre-esecuzione4

V3 preservata e mai eseguita. Si limita anche la connessione iniziale WebSocket a10secondi, con rifiuto su errore/chiusura/uscita del proprio child e rimozione degli handler iniziali. Nessuna modifica a coorte o calcoli.

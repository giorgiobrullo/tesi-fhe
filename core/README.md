# Core Python storico

Questa cartella contiene le utility Python/Concrete condivise dagli esperimenti
iniziali e dai benchmark: client/server FHE, matching, dataset, quantizzazione
e metriche.

Il core exact-ID più recente usa Rust e TFHE-rs 1.7.0. Si trova nel
[runtime mantenuto](../runtime/README.md), con la
[libreria](../runtime/core/src/lib.rs) e il servizio
che ne preserva il contratto di runtime. Non è un sostituto diretto delle API
Python di questa cartella. Gli snapshot Rust negli esperimenti 17–26 servono
a conservare le versioni realmente confrontate.

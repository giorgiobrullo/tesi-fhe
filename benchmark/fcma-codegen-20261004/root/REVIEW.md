# FCMA: revisione prima della compilazione

4 ottobre 2026. **PREBUILD_PASS** per il solo helper isolato e protocollo compile-only, seguito da una sola invocazione metadata `--capabilities`. Nessuna build o esecuzione effettuata dal reviewer; nessuna prova di velocità o correttezza FHE ottenuta. Questa nota resta immutabile dopo il gate; l'eventuale codegen avrà una review separata.

Letti integralmente protocollo, Cargo.toml/lock, main.rs, HELPER_SOURCE, FCMA_BOUND, BUILD_SETTINGS, BUILD_DRIVER e DEPENDENCY_BINDING. Il lock fissa pulp0.22.3 e la checksum della cache già dichiarata; il helper non dipende da TFHE. Le quattro identità primarie pulp aarch64/lib/Cargo e TFHE ggsw corrispondono ai byte/hash citati. La compilazione proposta è offline/locked, release opt3/CGU1/LTOoff, aarch64 e senza override osservati. La verifica degli archivi dipendenza e la liveness/preservazione immediata del lancio restano receipt del root, non una nuova attestazione fatta qui.

I wrapper safe accettano token Neon/NeonFcma, non chiamano costruttori unchecked. Geometry assert output/lhs2048 e rhs1024, C64_LANES1, chunks_exact e zip coprono due output completi senza tail: il ramo First sovrascrive con mul_c64s, MAC usa mul_add_c64s sul valore actual. Il boundary coincide con TFHE ggsw650–674 riletto; non sono incluse FFT, decomposizioni o chiavi. Il token fa passare WithSimd attraverso la vectorize primaria corrispondente.

Main accetta soltanto `--capabilities`, rifiuta argomenti extra, conserva i puntatori ai due wrapper con black_box senza invocarli e legge soltanto feature Rust/factory checked. Non crea operandi, non esegue aritmetica del probe, non misura tempi. Exit0 richiede entrambe le factory, exit1 indica indisponibilità dopo il JSON, exit2 argomenti invalidi. L'invocazione unica è un limite del launcher/protocollo, non un contatore interno al binario. BUILD_DRIVER contiene soltanto la compilazione e blocca un precedente BUILD.json; non lancia il target e non controlla processi esistenti.

La nuova derivazione FCMA è valida sotto le premesse RN/FMA correttamente arrotondata, underflow graduale, segni/lane esatti e finitezza senza overflow. FCMLA0 produce c+P, poi FCMLA90 aggiunge Q; il fattore k=u(2+u) e d=(2+u)sqrt2*eta seguono dal nuovo ordine, senza importare automaticamente il grafo Neon. First e MAC mantengono gli stessi H/beta e il prefisso First actual. La composizione ordinaria First+un MAC per ciascuno dei1024 modi dà k(2+k)B0+kB1+32(2+k)d. Nessuna osservazione di feature o presenza di FCMLA certificherà queste premesse, cap effettivi, storia, inverse, map, rumore, real lift o budget completo.

Non si presume uguaglianza bit per bit. Per il prossimo controllo readonly bisognerà seguire gli eventuali thunk solo a destinazioni univoche, separare First/MAC e contare gli effettivi loop; non equiparare questo caller fisso all'intero dispatch del servizio. Nessun benchmark o integrazione nella baseline è qualificato da PREBUILD_PASS.

Identità dirette del gate:

- PROTOCOL.md:1858B, `2d4a0960ca88e220e27f3d05f2970bcbe536393fc4ef7b13683587850a342d48`.
- probe/Cargo.toml:228B, `3010be99def04ec4257692c353bc82505179cf1b390064089820683208bfb075`; Cargo.lock:2966B, `d091029dccf1939dbb573d3a658f273bacd53b88ea0c95d83f296c5bd13dd729`.
- probe/src/main.rs:3904B, `420c3f98e5fa37fa538b1c9a671c030cf660658843973903ab1eadcadb9f2ae5`.
- HELPER_SOURCE.md:2865B, `8b2d1749e477bab0efe841c95662d76a23edd0e5e6364b44c622b6f63174aa5a`.
- FCMA_BOUND.md:4403B, `cfae8a0681deb835760105825ce86f1247c908ed8abfe3f8e7f0dfdb6548a4d3`.
- BUILD_SETTINGS.json:737B, `dcfa60cd209dfc73bed4ac0e229e09c9f7300056c6d43994f25ac318fd12cb41`; BUILD_DRIVER.py:3519B, `1b141ce3184a9913b00078bea470ce6c9b34a7664b023e1fc1288ae5c89e3089`; DEPENDENCY_BINDING.json:3151B, `5ac51c479f189288fc215f5164f41bda63a5963c9fe9c7e449f3a2a526edbc7f`.

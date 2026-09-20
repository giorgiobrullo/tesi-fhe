# Risultati storici e correzioni

[Indice dei risultati](../../findings.md) · [Repository](../../README.md)

Risultati al 9 settembre 2026. Le percentuali si riferiscono ai singoli
confronti e non si sommano. Le prove empiriche non stabiliscono un limite
alla probabilità di fallimento del circuito.

## F0–F83 - Risultati storici e correzioni consolidate

La tabella riassume i principali risultati dei primi esperimenti, includendo
le correzioni emerse nelle prove successive. I formati e le prestazioni delle
versioni iniziali non descrivono automaticamente l'implementazione attuale.

| Identificatori | Risultato che rimane, con le correzioni successive |
|---|---|
| F0–F3 | Concrete è stato eseguito nativamente su macOS arm64. La galleria pubblica consente prodotti cifrato×chiaro e richiede la corretta espansione del punteggio; non elimina da sola i problemi del modello di minaccia. |
| F4–F10 | PCA e descrittori locali hanno prototipi e benchmark conservati. I risultati sui dataset semplici non si trasferiscono ai benchmark difficili o al riconoscimento open-set 1:N. |
| F11–F14 | Argmin+soglia è implementabile; un inputset di compilazione non è un dominio di sicurezza. Gli embedding CNN migliorano le prove biometriche rispetto ai descrittori precedenti; quantizzazione e protocollo vanno valutati separatamente. |
| F15–F19 | Profondità, taglia della galleria e dominio dei volti cambiano l'accuratezza osservata. I primi numeri con un solo seed sono circoscritti e rinviano alle successive verifiche multi-seed; nessun tetto universale di accuratezza è dimostrato. |
| F20–F24 | Sono state confrontate compressione degli embedding, argmin server e strategie a blocchi in Concrete. Funzione restituita, interazione e minaccia determinano se un confronto preserva il contratto. |
| F25–F28 | Il test Concrete su Tesla T4 e i tornei/controlli a soglia hanno risultati propri. Non qualificano il successivo circuito custom GPU né dimostrano limiti generali di GPU o TFHE. La lettura della letteratura F26 è storica e corretta dagli audit successivi. |
| F29–F34 | Scaling DigiFace, divario di dominio e prodotto scalare leveled hanno misure nelle rispettive prove. Il rapporto storico Concrete/TFHE-rs di circa 100× riguarda l'argmin, non l'intera applicazione; i report 10 e 13 attribuiscono i tempi Concrete a macchine diverse, quindi non documentano un confronto controllato sullo stesso hardware. |
| F35–F39 | Il protocollo distingue identificazione e decisione di accesso. Gli otto bit sono una verifica in chiaro della quantizzazione; il torneo radix e la prima CKKS hanno benchmark separati. Il comparatore diretto a un PBS di F37 è invalidato vicino alla soglia da F68. |
| F40–F43 | Ridurre l'output riduce l'informazione esposta, ma conserva un oracolo applicativo. Query compatta, prototipo a tre ruoli e scaling storico fino a N1024 non validano il comparatore invalido né il contratto exact-ID corrente. |
| F44–F49 | GhostFaceNet e fusione multi-frame hanno verifiche biometriche specifiche. Parametri, ponti e codifiche hanno prove distinte. Le latenze del servizio pre-fold F49 restano storiche: i suoi casi facili non provano la frontiera riparata successivamente. |
| F50–F55 | Rumore PBS, codifica dell'uscita e rumore composto sono obblighi diversi. La primitiva a galleria GGSW cifrata riesce senza validare la decisione completa; il torneo con circuit bootstrapping provato non è un argmin esatto. Z-norm ha effetti biometrici circoscritti. |
| F56–F61 | Il bound e i controlli della galleria risolvono l'overflow nel dominio verificato, non l'origine biometrica di un probe arbitrario. Cascata, packing e multi-bit hanno esiti propri; l'output minimale non chiude gli attacchi applicativi. |
| F62–F67 | Confronti di sicurezza e prestazioni richiedono parametri e funzioni comparabili. Il contributo del progetto è implementazione, integrazione e valutazione, senza pretesa di priorità. Le negative di ammortizzazione/scaling sono circoscritte; CKKS deve includere i rifiuti open-set. |
| F68–F70 | L'audit invalida la soglia diretta, ritira il percorso residuale da 14 PBS e conserva il fallback da 9. Periodic-fold ripara empiricamente la frontiera con tre PBS/template; è ancora distinto dal successivo exact-ID e da una prova di probabilità globale. |
| F71–F73 | F71 stabilisce primo minimo+soglia del vincitore+0/ID. A28 elimina 508 KS a N127; A29 riduce il tempo dell'8,876% nel suo confronto appaiato. La singola LWE e la specifica del servizio di allora non sono il formato attuale a tre cifre. |
| F74–F76 | A33 viene integrato e poi promosso con 13,734% nel confronto A29/A33; A38 dà 13,828% nel proprio confronto. Le suite precedenti da 632 casi appartengono alle revisioni indicate nelle fonti, senza trasferimento alle revisioni nuove. |
| F77–F80 | A41 passa 29/29 casi con due LWE p16; A44 passa 120/120 ma conserva il bound raw condizionale. A62 materializza A50+A53 con 3390 BR e 142/142 casi di componente. A64 è un progetto statico checked, non un circuito compilato o misurato. |
| F81 | A73 confronta A62/A66, non A23/A66: 22,2018% di miglioramento a 16 thread e 2,2628% di peggioramento a un thread. Il conteggio A23→A66 e le suite 632 sono fatti separati. I successivi Head/PFKS, BGV e common-mask superano le vecchie descrizioni di stato senza rendere valide le vecchie costruzioni fallite. |
| F82 | Domini A124 eseguiti: N64 `[-1019,2317]`, N127/128 `[-1019,2329]`. BR di estrazione/selezione/scan a N128: 1664+1615+136=3415; a N127: 1651+1603+136=3390. Conteggi e tagli sovrapposti non sono risparmi sommabili. Il margine nominale p128 non prova la coda del circuito raw. |
| F83 | A124 termina 21 celle, 294 uscite corrette e 210 misure. L'audit successivo classifica 8 celle valide ai controlli pre/post, 12 con attività post elevata e una senza metadati driver. Il PASS originario non richiedeva quel successivo criterio post. Nessun monitor interno alla cella prova isolamento continuo; thread, carico e rapporti di stadio non identificano causalmente contributi degli E-core, copie, KS o un tetto allo scheduler. |

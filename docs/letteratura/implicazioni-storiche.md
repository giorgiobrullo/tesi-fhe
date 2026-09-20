# Implicazioni per le revisioni A28/A29/A33

[Indice della rassegna](../../letteratura.md) · [Fonti](fonti.md) · [Repository](../../README.md)

Rassegna al 2 settembre 2026. «Corrente», «promossa» e le prove ancora da
svolgere si riferiscono alle revisioni A28/A29/A33 a quella data. Gli sviluppi
successivi sono descritti nei [risultati del 9 settembre](../../findings.md).

## 6. Implicazioni

1. Concrete/TFHE si inserisce in una linea di lavori TFHE sul problema
   1:N considerato (Cong et al., Blind Counting Sort, RevoLUT, k-NN simmetrico PSD'22), e Cong/PSD'22
   condividono query cifrata e database in chiaro. Argmin, min+label e top-k in TFHE, così come la
   selezione per prefisso in FHE, hanno quindi precedenti. Il contributo riguarda la costruzione specifica,
   senza rivendicare una nuova primitiva, il primo argmin TFHE o il primo exact nearest-ID cifrato. Erkin restituisce
   `[Id]` cifrato; Sadeghi realizza la stessa funzione applicativa nel garbled circuit e consegna
   `r` in chiaro al client. Entrambi anticipano la soglia globale
   applicata al minimo, mentre Erkin è il precedente diretto per l'uscita cifrata `0`/ID;
   Kolesnikov et al. anticipano il tie-break sul primo minimo e Azogagh la
   stabilità TFHE con label. Il POC Zama e WO2025027253 documentano inoltre precedenti dell'architettura generale
   Concrete/TFHE o single-server, pur senza i dettagli A28.
2. Un puro bit di membership è più economico e con minore leakage, ma non soddisfa il requisito
   di identificazione. Exact nearest-ID seguito da una soglia globale soddisfa quel requisito
   e compare in letteratura dal 2009. Il contratto più stretto corrente fa prima l'argmin e
   poi seleziona e applica la soglia `T[k]` del solo vincitore; SCiFI rende anche questa distinzione
   concettualmente vicina, pur senza pubblicarne la stessa realizzazione. Il periodic-fold
   `any_match` resta una baseline scartata.
3. La galleria in chiaro consente prodotti enc×plaintext senza PBS e riduce il costo
   del calcolo. Il modello assume però che il server conosca i template della galleria.
4. CKKS offre forte scalabilità sotto modelli diversi: IDFace raggiunge 1 M template con
   selezione split-trust e argmax in chiaro sul Key Server; Blind-Match ottiene elevato throughput
   lasciando l'argmax al client. Nessuno dei due realizza il contratto exact-ID single-server
   corrente.
5. Il contributo della tesi è la progettazione, implementazione, integrazione e validazione
   sperimentale dello specifico co-design TFHE A28/A29 e, come candidato pre-promozione, della
   specializzazione A33. Nelle pubblicazioni accademiche/ePrint
   esaminate fino al 2 settembre 2026 non è stato individuato un prototipo valutato che riproduca
   congiuntamente tutti i dettagli A28: doppia vista full/modulo 16 su supporti disgiunti dello
   stesso GLWE, dominio intero bounded a 12 bit, selezione cifrata di `T[k]` e singolo ciphertext
   `0`/ID. È una constatazione sul corpus, non priorità, brevettabilità o freedom-to-operate; la
   ricerca brevettuale non è completa. L'esattezza è rispetto all'oracolo clear intero sul
   dominio quantizzato e bounded dichiarato, salvo fallimento della valutazione/decrittazione FHE;
   il `p-fail` composto non ha ancora un bound formale.
6. La fusione multi-output A29 non può essere presentata come nuova primitiva: Carpov et
   al., Chillotti et al. e FRAST anticipano multi-output, blind rotation condivisa ed estrazione di
   bit riusati per una correzione. Non è stata identificata nelle fonti esaminate la stessa
   integrazione mixed-scale dentro il co-design precedente. A29 è ora l'ultimo snapshot promosso
   e congelato; A33 resta un candidato nel worktree. A29 passa 198/198 boundary su tre chiavi
   fresche e 198/198 query semantiche su
   `N=1..8,64,127,128` con 33 coppie di chiavi fresche, osservando 4.965 PBS nel percorso uniforme
   N=127. Passa inoltre il replay diagnostico DigiFace del probe 87 con codice 88 e zero mismatch,
   la regressione di frontiera 80/80, la suite primaria 632/632 con zero errori/discrepanze e l'E2E
   Docker 6/6. Il paired A28/A29 preserva 72/72 output e misura -8,876% [8,092%, 9,728%] su cinque
   probe di frontiera fissati, ciascuno ripetuto 12 volte nei tre blocchi-chiave (60 coppie, non 60
   casi biometrici indipendenti), con 57/60 vittorie e condizionamento al carico alto del run. Il
   bound formale della `p-fail`
   resta separatamente aperto.
7. A33 non introduce una nuova primitiva multi-output: `PBSmanyLUT` e le domande Axell anticipano
   una blind rotation con test vector interlacciato e più sample extraction, anche a posizioni
   distanti e con output diversi. Il candidato di contributo è soltanto la specializzazione
   end-to-end `residuo sparso -> r/flag signed -> pesi 1/3 -> canonicalizzazione -> exact-ID`.
   Il core completo mirato e la frontiera 80/80 sono positivi, ma finché non supera suite primaria,
   Docker, paired A29/A33 e accounting condizionale della `p-fail` va chiamato candidato integrato,
   non revisione promossa o novità crittografica. Confronti matched con due PBS indipendenti,
   `ManyLookupTable` stock e pesi applicati successivamente possono rafforzare l'attribuzione
   sperimentale del co-design, non rendere nuova la primitiva.
8. Yu et al., WAHC 2024, pubblicano già priority encoder e sintesi FBS multi-value.
   L'eventuale contributo di A34 riguarda quindi la specifica combinazione exact-ID.

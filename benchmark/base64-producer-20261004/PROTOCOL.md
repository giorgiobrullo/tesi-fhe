# Pilot del solo produttore base64

4 ottobre 2026. Questo helper di test usa una sola famiglia nuova, senza caricare chiavi salvate. Non qualifica il servizio mantenuto, il confronto, la selezione, la latenza o una probabilità di fallimento. Nessuna esecuzione è stata fatta dall'autore del sorgente.

## Sequenza fissata

Il test ignorato `service::base64_probe::normalized_public_fixtures_without_timing` richiede `BASE64_PRODUCER_OUTPUT_DIR`, percorso assoluto non esistente. Il launcher può fornire `BASE64_PRODUCER_BUILD_RUSTC` al compilatore. Il test crea esclusivamente quella directory e i suoi nuovi file.

Una famiglia client Standard del preset `V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64` genera l'ordinaria, la Head15×2 e PFKS tramite `service::generate_bundle`. La geometria reale è verificata: small859, big2048, GLWE2/N2048, KS3×5, ordinaria23×1, Head15×2. Il piano FFT1024 è Dif4/base1024; il pool ha16 thread. Il profiling resta disabilitato. Il preset canonico non è una certificazione delle LUT128 personalizzate.

I primi otto casi sono eseguiti nell'ordine **63,64,0,4095,127,128,1023,1024**. Ogni caso cifra un nuovo LWE sotto il big secret, con messaggio `x*2^51` e la distribuzione pubblica di rumore GLWE del preset. Si ferma al primo risultato errato o non canonico.

Solo dopo otto PASS si cifra un nuovo GLWE query `(1,1)` nel formato reale51/60. I template distinti sono `e0,e1`, con norme1 e soglie−2/−1. Il piano corrente ammette il dominio[−63,65]; gli score pubblici−1/−1 sono normalizzati62/62. `head_pfks_score_prefix_with_parallel` viene chiamato una volta e i suoi stessi due LWE, senza osservazioni intermedie né riparazioni, entrano nel produttore. Questo è un solo nono caso, non due righe aggiuntive.

## Operazioni effettive

Per ciascuno score: copia input51−`B`, con `B=2^56`; A112 corrected KS; A98 exact MS log12; Head con valori `floor(m/2)*B−O`, `O=63*2^55`, m0..127. Ogni valore è ripetuto16 volte, i primi8 coefficienti sono negati e il body è ruotato a sinistra8. Una BR Head e l'estrazione0 producono H; si aggiunge O.

Il dirty è `32*(input−2H)` su tutti i coefficienti nativi. Una seconda A112 KS/A98 MS produce **un solo oggetto switched**, usato da due BR scalari ordinarie su accumulatori nuovi: low `(r mod64)*2^57`, carry `floor(r/64)*2^57`, r0..127, stesso layout128. Le uscite finali sono `[high,low]=[2H+carry,low]` a57. Non si usa il factor-pair condiviso, non si aggiunge un bias e non si osserva H.

I contatori locali vengono incrementati nei callsite reali: **BR3,KS2,samples3,gadget_levels4 per score**; il nono caso con due score ha6/4/6/8. Il costo del prefisso lineare non è incluso in questi contatori del produttore. La somma livelli usa i livelli delle due chiavi reali, verificati prima dei casi.

## Registrazione e stop

`rows.jsonl` contiene metadata, fino a9 record `case`, e `complete`. Si decifrano solo i chunk finali: arrotondamento torus nativo a57, valore canonico in0..63, oracle pubblico `[x/64,x%64]`. Un valore non canonico è `null`, con `canonical=false`; nessun torus grezzo, fase privata, indirizzo, rumore o bit segreto è registrato. Non ci sono clock o misure di tempo.

Ogni caso salva sempre `input_envelope` come `Vec<Lwe>`. Un fallimento salva un'unica `failed_outputs_envelope` come `Vec<[Lwe;2]>` dei chunk finali; sui PASS il campo è null. Client e bundle sono serializzati una volta prima dei casi; il GLWE del prefisso è salvato solo se raggiunto, nel campo `query_envelope` del caso8 (null negli altri). Le envelope hanno header pubblico, magic `B64PENV1`, lunghezza header little-endian e payload bincode1.3.3 opaco, scritto in streaming con byte e SHA256. Il helper non legge mai questi file.

La completion esclusiva è scritta anche in `COMPLETE.json`: `PRODUCER_PASS_9_CHECKS` con9 casi oppure `PRODUCER_REJECTED` con il numero realmente eseguito e i successivi non eseguiti. Il rifiuto scientifico è scritto prima del panic. Errori di configurazione/I/O e inconsistenze interne hanno prefissi separati `CONFIG_OR_IO_FAILURE` e `INTERNAL_CONFIGURATION_FAILURE` e non diventano un PASS.

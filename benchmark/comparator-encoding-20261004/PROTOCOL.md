# Primo controllo del comparatore a due cifre

Helper autonomo TFHE-rs 1.8.1 CPU. Una sola famiglia ordinaria fresca,
parametri `V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, vero ramo
Standard/Classic e modulus switch Standard. Dimensioni pubbliche: LWE
piccolo859, GLWE size2 (dimensione1), N2048, LWE grande2048. Il piano FFT
Dif4/base1024 viene impostato prima delle chiavi. Release opt3/CGU1/LTOoff;
il root fornisce `SCRATCH_BUILD_RUSTC` e conserva build/lock offline.

Il programma riceve un solo argomento: una nuova directory di output,
con genitore esistente. Rifiuta una directory già presente. Le chiavi
client/server sono salvate una volta come file bincode1 opachi; nei report
compaiono soltanto nomi, dimensioni, byte e hash SHA256. Cifratura ordinaria
tramite `encryption_key_and_noise` e decrittazione ordinaria del risultato;
nessuna ispezione dei bit del segreto, delle fasi o degli spettri. Il decoder
arrotonda a2^59 e restituisce soltanto -1/0/+1 oppure null se fuori alfabeto.

Otto coppie prefissate di cifre [middle,low], percorse in quattro round:
0=0, 0<1, 1>0, [1,0]>[0,15], inverso, [15,15]>[0,0], inverso,
[15,15]=[15,15]. Totale massimo32 casi, senza cambiare chiave o riprovare.
Per ogni caso la reference cifra nuovamente [top=0,middle,low] a2^59 ed
esegue tre ternary PBS: KS → Standard MS → stock BR → estrazione grado0.
Body pubblico +2^59 negli indici64…1983, zero altrove. Ogni ternario deve
corrispondere alla differenza della propria cifra; il primo nonzero deve
corrispondere all'oracolo integer. Un errore reference ferma il programma
con exit1 e un record distinto: non viene classificato come errore candidate.

Il candidate cifra nuovamente le sole middle/low a2^55, calcola linearmente
16*(left_middle−right_middle)+(left_low−right_low) e fa un solo KS. Quel
medesimo ciphertext piccolo alimenta due rami: raw e correzione pubblica
mean-only. La correzione è esattamente lo scalare restituito da
`lwe_ciphertext_centered_binary_modulus_switch(..., log12).into_raw_parts().1`
più2^51, aggiunto soltanto al body; la vista centered non viene passata alla
BR. Entrambi eseguono Standard MS/stock BR/estrazione sulla stessa LUT:
+2^59 negli indici **4…2043 inclusi**, zero altrove. Non si registrano la
correzione né gli indirizzi. Massimo cinque BR per caso: tre reference,
una raw e una centered. Nessun refresh del controllo è provato qui.

Il primo raw failure è preservato e non causa un retry; i casi continuano.
Il primo centered failure, dopo reference corretta, preserva i ciphertext
ed emette riga completa e risultato `CANDIDATE_REJECTED`, exit2. Per ogni
fallimento preservato gli envelope contengono, in ordine: quattro cifrati
candidate [left_middle,right_middle,left_low,right_low], packed, KS raw,
KS corrected, poi per le tre cifre reference [left,right,difference]. Gli
output contengono [raw,centered] e i tre output reference. In un reference
failure si salvano soltanto i nove input reference e i suoi tre output.
Tutti i file sono create-new; un errore di configurazione/I/O causa panic,
mai exit2. Ogni riga JSONL viene flushata; stdout contiene solo quei record.

Exit0 significa32 centered pass. Se raw ha fallito, lo stato finale è
`CONDITIONAL_CENTERED_PASS`; altrimenti `PASS`. Nessun risultato dimostra
la correttezza di Head, conversione delle scale, PFKS, selettore, refresh,
torneo o pipeline completa. Nessun p-fail viene ereditato dal parametro
standard per l'encoding55, nessun timing o guadagno viene misurato.

Solo il root costruisce e avvia dopo source review e nuova liveness.
L'autore non ha eseguito build, test, keygen o valutazioni FHE. Nessuna
modifica al runtime mantenuto, nessuna vecchia chiave caricata, nessun
modello/checker precedente importato, nessuna operazione Git o remota.

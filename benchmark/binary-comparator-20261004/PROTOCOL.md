# Prova primitiva della LUT binaria

Nuovo helper derivato soltanto dal recente probe E, con una candidata
distinta. TFHE-rs1.8.1 CPU, parametri
`V0_11_PARAM_MESSAGE_1_CARRY_3_KS_PBS_GAUSSIAN_2M64`, Standard/Classic e
modulus switch Standard. Dimensioni pubbliche859/GLWE size2/N2048;
chiave di cifratura/output LWE grande2048. FFT Dif4/base1024 prima delle
chiavi; release opt3/CGU1/LTOoff. Il root lega compiler, lock e build
offline e fornisce `SCRATCH_BUILD_RUSTC`.

Argomento unico: NEW_OUTPUT_DIRECTORY, genitore esistente, directory
create-new. Una sola famiglia ordinaria fresca generata dal helper,
senza caricare chiavi precedenti, retry o resampling. Chiavi client/server
salvate una volta come envelope opache bincode1; nei JSONL soltanto nomi,
byte e SHA256. Cifratura tramite `encryption_key_and_noise`; decrittazione
ordinaria seguita da arrotondamento a2^59. Si espone soltanto -1/0/+1 o
null fuori alfabeto, mai fasi, segreti, spettri o correzioni.

Un solo round delle otto coppie E, in questo ordine: [0,0]=[0,0],
[0,0]<[0,1], inverso, [1,0]>[0,15], inverso, [15,15]>[0,0], inverso,
[15,15]=[15,15]. Campo `oracle`: segno ternario della differenza integer.
Campo `oracle_binary`: -1 quando left<=right, +1 quando left>right.
Il pareggio binario viene quindi assegnato a Left.

Per ogni caso la reference cifra nuovamente [top0,middle,low] a2^59:
tre PBS ternarie KS → Standard MS → stock BR → extraction grado0;
body +2^59 negli indici64…1983, zero altrove. Si verifica ogni ternario
contro la differenza della cifra e il primo nonzero contro `oracle`.
Un errore reference ferma con `REFERENCE_FAILED`, exit1 distinto.

La candidata cifra nuovamente middle/low a2^55, calcola linearmente
16*(left_middle−right_middle)+(left_low−right_low), esegue KS e applica
la stessa correzione pubblica mean-only di E: correzione stock di
`lwe_ciphertext_centered_binary_modulus_switch(...,log12)` più2^51 nel
body. La vista centered non alimenta la BR. Segue soltanto Standard
MS → stock BR → extraction grado0, senza ramo raw. Body della nuova
LUT: **−2^59 agli indici0…3, zero a4, +2^59 agli indici5…2047**.
Il risultato deve coincidere con `oracle_binary`, anche nei pareggi.

Massimo8 casi e4 BR per caso, nessun refresh/PFKS/torneo. Stop al primo
candidate failure dopo reference corretta, con riga completa,
`CANDIDATE_REJECTED` ed exit2. Si conservano envelope opache del caso:
input [left_middle,right_middle,left_low,right_low,packed,KS raw,KS
corrected], poi [left,right,difference] per le tre cifre reference;
output [candidate,reference top,reference middle,reference low]. Per
reference failure si salvano soltanto i nove input e tre output reference.
File create-new, JSONL flush dopo ogni riga; panic/configurazione/I/O
restano distinti da exit2. Nessuna ripetizione dopo un errore.

Exit0 significa esclusivamente `PRIMITIVE_PASS_8_CASES`. Non qualifica
rumore, p-fail, input Head, conversioni, refresh, PFKS, torneo o 0/ID;
non misura tempi o guadagni e non modifica il runtime mantenuto.
La geometria di riferimento è E/math/BINARY_TIE.md, già verificata dal
root: margine uniforme intero3, non garanzia di rumore.

Solo il root costruisce/avvia dopo review e liveness nuova. L'autore
prepara soltanto questi tre file, senza build, test, chiavi o FHE,
modelli/checker precedenti, Git, rete o controllo di processi.

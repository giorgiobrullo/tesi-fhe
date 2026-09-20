# Progressione FHE: nuove misure comuni

La figura collega le mediane delle versioni in due sezioni, con un solo stacco. Ogni punto deriva dalla nuova campagna locale; i vecchi tempi non sono stati riutilizzati.

La prima sezione confronta Concrete sequenziale e TFHE iniziale sul calcolo dei punteggi e sul primo argmin, con N=8 e 64 coordinate. La seconda confronta dieci implementazioni destinate al compito 0/ID con N=127, 512 coordinate e soglia uniforme T=4: ID del primo minimo se il suo punteggio è minore o uguale a 4, altrimenti 0.

Lo stacco cambia compito e dimensione: non esiste una percentuale di miglioramento comparabile fra i due lati. A28 è il primo sorgente exact recuperato e rimisurato; A23/A25 non sono stati ricostruiti né inseriti con i loro vecchi tempi.

La nuova campagna 0/ID conta 450/450 risultati corretti, senza nuovi errori osservati. La croce rossa indica esclusivamente il precedente errore irrisolto di Head generale. Il tempo di questa versione resta descrittivo e non qualifica un miglioramento exact. I conteggi di correttezza includono il riscaldamento; i tempi riassumono soltanto le osservazioni misurate. La linea collega tempi in ordine di sviluppo; non certifica la correttezza di ogni punto.

## Correttezza

| Versione | Corrette / totali | Errori misurati | Errore precedente irrisolto |
|---|---:|---:|---|
| A28 | 45 / 45 | 0 | no |
| A29 | 45 / 45 | 0 | no |
| A33 | 45 / 45 | 0 | no |
| A38 | 45 / 45 | 0 | no |
| A66 | 45 / 45 | 0 | no |
| R3 | 45 / 45 | 0 | no |
| Head M | 45 / 45 | 0 | no |
| Head generale | 45 / 45 | 0 | sì |
| FFT + CGU1 | 45 / 45 | 0 | no |
| Finale | 45 / 45 | 0 | no |

Il primo tentativo si è fermato dopo 269 risultati: 268 corretti e uno errato. Head generale ha restituito ID75 anziché ID1 nel caso tie_first_last. Il replay della stessa chiave e dello stesso input ha riprodotto gli stessi ciphertext. È una ripetizione dello stesso errore, non un nuovo campione indipendente. Questi tempi restano separati dalle 450 nuove osservazioni e non entrano nelle mediane. Nella nuova campagna Head generale ha 45/45 risultati corretti; il precedente errore rimane irrisolto.

## File

- `progressione.png`: figura principale, scala logaritmica esplicitata sull’asse.
- `progressione-email.png`: stessa figura, più leggera.
- `progressione.svg`: versione vettoriale.
- `progressione-lineare.png`: stessi dati su scala lineare; i tempi piccoli occupano meno spazio.
- `punti.csv`: mediane e quartili numerici.
- `osservazioni-exact.csv` e `osservazioni-prototipi.csv`: tutte le durate, compreso il riscaldamento indicato a parte.
- `dati.json`: punti, metodo e collegamento ai controlli indipendenti.

## Tempi misurati

I quartili descrivono la dispersione delle osservazioni. Non sono intervalli di confidenza.

| Versione | Misure | Mediana (s) | Intervallo interquartile (s) |
|---|---:|---:|---:|
| Concrete | 18 | 264.797785 | 254.585034 - 271.403972 |
| TFHE iniziale | 18 | 49.767460 | 49.699728 - 49.869376 |
| A28 | 30 | 7.351781 | 7.319670 - 7.399280 |
| A29 | 30 | 6.667234 | 6.639578 - 6.748380 |
| A33 | 30 | 5.595930 | 5.571611 - 5.639238 |
| A38 | 30 | 4.764889 | 4.745149 - 4.822369 |
| A66 | 30 | 4.151291 | 4.122019 - 4.192330 |
| R3 | 30 | 3.019729 | 2.988998 - 3.042507 |
| Head M | 30 | 2.094266 | 2.066472 - 2.110409 |
| Head generale | 30 | 2.080595 | 2.065626 - 2.096758 |
| FFT + CGU1 | 30 | 2.082289 | 2.064327 - 2.095219 |
| Finale | 30 | 1.622570 | 1.611279 - 1.641609 |

## Confronti appaiati

La variazione è 100 × (media geometrica del rapporto dei tempi - 1), usando gli stessi gruppi comparativi. Un valore negativo indica meno tempo. Questa quantità è distinta dal rapporto delle due mediane.

| Candidato / riferimento | Variazione del tempo | Candidato più veloce / gruppi | Qualifica exact |
|---|---:|---:|---|
| TFHE iniziale / Concrete | -81.2735% | 18 / 18 | non applicabile (argmin) |
| A29 / A28 | -9.0389% | 30 / 30 | osservata nei controlli |
| A33 / A29 | -16.1458% | 30 / 30 | osservata nei controlli |
| A38 / A33 | -14.7587% | 30 / 30 | osservata nei controlli |
| A66 / A38 | -12.9233% | 30 / 30 | osservata nei controlli |
| R3 / A66 | -27.4664% | 30 / 30 | osservata nei controlli |
| Head M / R3 | -30.8895% | 30 / 30 | osservata nei controlli |
| Head generale / Head M | -0.1029% | 14 / 30 | no, errore precedente irrisolto |
| FFT + CGU1 / Head generale | +0.3589% | 14 / 30 | no, errore precedente irrisolto |
| Finale / FFT + CGU1 | -21.9940% | 30 / 30 | osservata nei controlli |

Finale / A28: variazione appaiata **-77.8052%**, con 30 gruppi più veloci su 30. Correttezza osservata nei controlli di entrambe le versioni.

## Condizioni e verifica

Apple M4 Max, 64 GiB, macOS 27.0; nuove compilazioni Rust 1.98.0/LLVM 22.1.8. Tutte le versioni exact usano 16 thread, ottimizzazione 3, CPU generica e nessuna LTO. Il passaggio FFT + CGU1 adotta FFT fissa Dif4 e una sola unità di compilazione; non introduce i 16 thread, già comuni. I prototipi conservano Concrete 2.11.0 e TFHE-rs 0.11.3; le versioni exact conservano librerie e parametri nativi.

Tre famiglie nuove per ciascun profilo nativo. Nei prototipi: tre scene, una ripetizione di riscaldamento e due misurate ciascuna. In exact: cinque scene, una ripetizione di riscaldamento e due misurate ciascuna. Ogni scena e famiglia ha uguale peso. Ordine delle versioni prefissato e bilanciato, esecuzioni FHE serializzate.

Sono controlli retrospettivi di primi/ultimi minimi, pareggi, uguaglianza alla soglia e rifiuto. Non sono nuove prove biometriche. I timer misurano il calcolo cifrato completo fino all’output nativo. Nella sezione exact includono anche viste dei template, norme e pianificazione per query. Sono esclusi compilazione, chiavi, cifratura, decifratura, serializzazione e scrittura dei risultati; non sono tempi della pagina web.

Le versioni preservano codifiche e parametri propri. A28-A38 condividono effettivamente chiavi e ciphertext entro il gruppo; le altre versioni sono abbinate per scena in chiaro e gruppo comparativo. La figura non attribuisce un passaggio composto a una sola ottimizzazione né attesta uguali garanzie crittografiche.

| Sezione misurata | Finestre | Carico esterno segnalato | Contabilizzazione incerta | Copertura campionata completa |
|---|---:|---:|---:|---:|
| Prototipi | 36 | 36 | 36 | 36 |
| Exact 0/ID | 300 | 300 | 196 | 300 |

Tutte le osservazioni previste sono conservate. Il campionamento del carico non prova isolamento continuo e non identifica da solo la causa di una variazione.

I lettori indipendenti verificano piani, ordine, oracoli, input/output, chiavi, sorgenti, chiusure dei processi e contabilità del carico. Le fasi terminali late-exact e early-exact sono ricalcolate direttamente dai ciphertext e dalle nuove chiavi locali, insieme a tutti i coefficienti degli input GLWE. Per i prototipi, la decifratura resta una testimonianza del worker nativo legata ai sorgenti. Questi test non stabiliscono un limite formale alla probabilità di fallimento dell’intero circuito.

Il primo tentativo Concrete si è interrotto durante il setup, prima di qualsiasi query. È conservato come fallimento di setup; il gate di recupero riusa soltanto quelle chiavi nuove e mai valutate. Tutte le famiglie principali generano invece nuove chiavi.

## Riproduzione delle statistiche e del grafico

I CSV contengono tutte le osservazioni della campagna, con la fase di
riscaldamento distinta dalle misure. `punti.csv` e `dati.json` riportano
mediane, quartili, conteggi di correttezza e condizioni della campagna.
La [guida pratica](../../../../docs/riproducibilita.md) spiega come leggere
le tabelle e rigenerare la [figura Matplotlib](../benchmark-comune-matplotlib-20260909/LEGGIMI.md).
Le tabelle consentono il controllo delle statistiche, non la ripetizione
delle decifrature originali. Una nuova prova FHE richiede nuove chiavi
e una propria esecuzione delle implementazioni.

# Invarianti del circuito exact-ID TFHE

**Data:** 2026-09-02  
**Oggetto:** audit statico del core `private_argmin` corrente  
**Stato dell'evidenza sperimentale:** la suite primaria da 632 query e' ancora in corso. I suoi risultati non sono usati in questo documento.

Questa nota ricostruisce il contratto e gli invarianti logici del circuito. Non propone claim di novita' e non trasforma il parametro nominale `log2_p_fail` di TFHE-rs in un bound end-to-end per questa composizione low-level.

## 1. Contratto

Il server riceve:

- un probe cifrato in un solo GLWE, presente in due layout coerenti: precisione completa a `Delta=2^52` e residuo modulo 16 a `Delta=2^60`;
- una galleria non cifrata di `N` template, con `1 <= N <= 128`;
- norma quadrata e soglia pubblica associate a ogni template;
- una chiave di valutazione, ma non la chiave segreta.

Il circuito restituisce un solo LWE:

- `0` se il primo template a distanza minima non supera la propria soglia;
- `i+1` se il primo template a distanza minima ha indice zero-based `i` e supera la propria soglia.

La distanza minima non fa parte dell'output. Questo contratto e' dichiarato nel modulo ([sorgente, L1-L6](../src/private_argmin.rs#L1-L6)) e nell'API pubblica ([sorgente, L822-L838](../src/private_argmin.rs#L822-L838)).

La semantica clear di riferimento ordina le coppie `(score, indice)`, applica soltanto la soglia del vincitore e codifica `0` oppure `indice+1` ([sorgente, L288-L313](../src/private_argmin.rs#L288-L313)).

## 2. Assunzioni di correttezza

### 2.1 Input honest e ben formato

La prova vale se il client cifra un probe che rispetta il contratto:

1. le coordinate dichiarate appartengono a `[-3,3]`;
2. la norma quadrata del probe e' al massimo `1024`;
3. i layout full e modulo 16 contengono lo stesso probe;
4. il formato, la chiave e i parametri crittografici sono quelli attesi.

Il server puo' verificare forma e modulo del ciphertext, ma non puo' verificare in chiaro le proprieta' semantiche del probe cifrato. Il sorgente dichiara esplicitamente questo confine ([sorgente, L824-L831](../src/private_argmin.rs#L824-L831)). In particolare, il circuito non costituisce una prova di conoscenza o di well-formedness contro un client malevolo.

### 2.2 Galleria e dominio

Per ogni template il server verifica dimensione, coordinate e norma dichiarata ([sorgente, L458-L489](../src/private_argmin.rs#L458-L489)). Il dominio deve essere ordinato, avere larghezza al massimo `4096` e coprire il bound di ogni template ([sorgente, L492-L532](../src/private_argmin.rs#L492-L532)).

Per il template `t_i`, il punteggio cifrato e'

```text
s_i = ||t_i||^2 - 2 <q,t_i>.
```

Rispetto alla distanza euclidea manca soltanto `||q||^2`, costante per tutti gli indici; pertanto `argmin_i s_i` coincide con `argmin_i ||q-t_i||^2`. La costruzione omomorfa del punteggio e' in [sorgente, L1095-L1127](../src/private_argmin.rs#L1095-L1127).

Da Cauchy-Schwarz e `||q||^2 <= 1024`:

```text
||t_i||^2 - 2 sqrt(||t_i||^2 * 1024)
    <= s_i <=
||t_i||^2 + 2 sqrt(||t_i||^2 * 1024).
```

Il codice usa il ceil intero della radice per ottenere un intervallo conservativo ([sorgente, L244-L285](../src/private_argmin.rs#L244-L285)). Sottraendo `domain.lower`, ogni punteggio valido appartiene a `[0,4095]` ed e' rappresentabile esattamente con 12 bit.

## 3. Invariante di selezione bit per bit

I bit dei punteggi traslati sono visitati dal piu' significativo al meno significativo ([sorgente, L888-L890](../src/private_argmin.rs#L888-L890)). Sia:

- `C_l` l'insieme dei candidati attivi prima del livello `l`;
- `b_i,l` il bit del punteggio dell'indice `i` al livello `l`;
- `z_i,l = c_i,l AND NOT b_i,l`;
- `a_l = OR_i z_i,l`.

Il circuito conserva il candidato `i` se e solo se

```text
c_i,l+1 = c_i,l AND (b_i,l != a_l).
```

La realizzazione e' in [sorgente, L1224-L1312](../src/private_argmin.rs#L1224-L1312).

**Invariante.** Dopo il livello `l`, `C_l` contiene esattamente gli indici il cui prefisso di `l` bit e' minimo tra tutti i punteggi.

**Prova per induzione.** Prima del primo livello tutti gli indici sono attivi, quindi l'invariante e' vero per il prefisso vuoto. Se almeno un candidato attivo ha bit zero, `a_l=1` e sopravvivono esattamente i candidati con bit zero. Se nessun candidato attivo ha bit zero, `a_l=0`, tutti hanno bit uno e sopravvivono tutti. In entrambi i casi si conserva precisamente il sottoinsieme con prefisso minimo. Dopo 12 livelli restano tutti e soli gli indici che realizzano il minimo globale. `a_l` e' inoltre il complemento del bit `l` del minimo: `minimum_bit_l = NOT a_l`.

## 4. Stato alternato `-1/0/+1`

Per evitare un PBS di normalizzazione dopo ogni bit, i livelli pari producono uno stato torus codificato e i livelli dispari lo riportano a Booleano fresco.

### 4.1 Passaggio Booleano -> codificato

Dato un candidato Booleano `c`, il suo indicatore zero `z=c AND NOT b` e `a=OR z`, il circuito costruisce linearmente

```text
e = -c - z + a.
```

Sugli stati raggiungibili:

| Stato logico | Condizione | `e` |
|---|---|---:|
| sopravvive con bit 0 | `c=1, z=1, a=1` | `-1` |
| sopravvive con bit 1 | `c=1, z=0, a=0` | `-1` |
| eliminato | `c=1, z=0, a=1` | `0` |
| gia' inattivo | `c=0, z=0, a in {0,1}` | `0` o `+1` |

Quindi `e=-1` identifica esattamente i candidati sopravvissuti; gli inattivi sono `0/+1` ([sorgente, L1278-L1291](../src/private_argmin.rs#L1278-L1291)).

### 4.2 Test dello zero sul livello dispari

Al livello successivo si valuta `e + w*b`, con `w in {1,2,4,8}`. Il codice modulo 16 e' `15` soltanto quando `e=-1` e `b=0`:

- un attivo con bit zero produce `-1`, cioe' codice 15;
- un attivo con bit uno produce `-1+w`, mai 15;
- un inattivo produce un valore tra 0 e 9, mai 15.

Il valore torus e' fisicamente `-Delta`, non il messaggio positivo `15*Delta`. Per la periodicita' negaciclica del PBS, l'ingresso fisico `-1` legge la casella logica 15 cambiandone il segno. La LUT deve quindi contenere `-1` nella casella 15 affinche' il PBS restituisca il Booleano positivo `+1`. Il codice usa `u64::MAX`, cioe' `-1` modulo `2^64` ([sorgente, L575-L585](../src/private_argmin.rs#L575-L585)).

### 4.3 Ritorno a Booleano

Siano `z'` l'indicatore fresco appena calcolato e `a'=OR z'`. Il circuito applica una LUT a

```text
-e + z' - a'.
```

Il codice raggiungibile vale uno esattamente per un candidato attivo che sopravvive al livello dispari; tutti gli inattivi producono codici diversi da uno. L'uscita torna quindi Booleana fresca ([sorgente, L1292-L1306](../src/private_argmin.rs#L1292-L1306)). L'enumerazione locale degli stati raggiungibili e' coperta dal test exhaustivo delle LUT ([sorgente, L1657-L1732](../src/private_argmin.rs#L1657-L1732)).

## 5. Scelta deterministica del primo minimo

Dopo i 12 livelli possono restare piu' candidati soltanto in caso di parita' esatta. Lo scan divide i candidati in gruppi di tre:

1. un OR produce il flag di ciascun gruppo;
2. un prefisso esclusivo radix-4 calcola se un gruppo precedente contiene un minimo;
3. per ogni indice si considerano il prefisso di gruppo e al massimo due predecessori locali.

Il prefisso ricorsivo e' definito in [sorgente, L767-L813](../src/private_argmin.rs#L767-L813); lo scan completo e' in [sorgente, L1315-L1349](../src/private_argmin.rs#L1315-L1349).

Per l'indice `i`, l'ingresso della LUT finale e'

```text
candidate_i - previous_group_present - local_previous_count.
```

Tra gli stati raggiungibili il codice e' uno se e solo se `candidate_i=1` e non esiste un candidato attivo con indice minore. Ne segue che esiste un solo winner e che, a parita' di punteggio, vince il primo indice della galleria. La tavola locale e' enumerata in [sorgente, L1751-L1764](../src/private_argmin.rs#L1751-L1764).

## 6. Soglia associata soltanto al winner

Ogni bit pubblico delle soglie definisce una maschera sugli indici. Il circuito applica l'OR ai soli winner abilitati dalla maschera:

- maschera vuota: zero pubblico;
- maschera piena: uno pubblico, poiche' esiste esattamente un winner;
- maschera parziale: OR dei winner selezionati.

Poiche' il winner e' one-hot, il risultato e' precisamente il bit della soglia associata a quel winner, non l'OR delle soglie di tutti i candidati o di tutti i match possibili ([sorgente, L1357-L1400](../src/private_argmin.rs#L1357-L1400)).

Una macchina a tre stati `less/equal/greater`, codificata come `0/2/4`, confronta il minimo con la soglia selezionata in 12 PBS. L'accettazione vale `minimum <= threshold`. Una soglia sotto `domain.lower` forza il rifiuto; una soglia sopra `domain.upper` puo' essere clampata all'upper bound, perche' ogni punteggio valido e' gia' minore o uguale a esso ([sorgente, L1405-L1427](../src/private_argmin.rs#L1405-L1427)).

Conseguenza: se il primo minimo ha soglia severa, una seconda identita' a pari punteggio o una identita' piu' lontana con soglia permissiva non puo' autorizzare la query. La semantica e' verificata anche dall'oracolo clear ([sorgente, L1575-L1596](../src/private_argmin.rs#L1575-L1596)).

## 7. Uscita `0` oppure `i+1`

Per ogni posizione binaria usata dai codici `1..N`, il circuito OR-riduce i winner il cui `indice+1` possiede quel bit. L'ultimo PBS emette direttamente un digit fresco con peso locale `1`, `2` o `4`. Tre digit e il tag di accettazione `8` formano un codice locale in `[0,15]`:

- senza tag, la LUT di gruppo emette zero;
- con tag, emette il payload a tre bit spostato della posizione del gruppo.

La somma di al massimo tre gruppi ricostruisce `indice+1` per `N<=128` ([sorgente, L1433-L1473](../src/private_argmin.rs#L1433-L1473)). Le maschere ricostruiscono tutti i codici supportati nel test [sorgente, L1767-L1783](../src/private_argmin.rs#L1767-L1783).

Quindi l'unico plaintext restituito e':

```text
code = accept * (first_argmin_index + 1).
```

## 8. Conteggio esatto dei PBS

Sia `R(k)` il numero di PBS necessario per un OR radix-4 di `k` ciphertext:

```text
R(0)=R(1)=0
R(k)=ceil(k/4) + R(ceil(k/4)),  k>1.
```

La funzione corrispondente e' in [sorgente, L316-L323](../src/private_argmin.rs#L316-L323).

### 8.1 Costo indipendente dalle soglie

Per `N` template:

- estrazione: `14N` PBS di correzione + `6N` ricodifiche = `20N`;
- selezione: `11N` test zero + `6N` normalizzazioni dispari + `12R(N)` OR = `17N + 12R(N)`;
- scan: `scan(N)` secondo [sorgente, L325-L355](../src/private_argmin.rs#L325-L355);
- confronto finale: 12 aggiornamenti + un tag = 13 PBS;
- codifica: `output(N)` secondo [sorgente, L357-L383](../src/private_argmin.rs#L357-L383).

Il termine lineare e' quindi `20N+17N=37N`.

### 8.2 Soglie arbitrarie

Ci sono tredici maschere pubbliche: dodici bit di soglia e la sentinella `threshold < lower`. Per la maschera `j`, con `k_j` indici abilitati:

```text
M_j = 0       se k_j in {0,N}
M_j = R(k_j)  altrimenti.
```

Il conteggio esatto e'

```text
PBS(N, thresholds)
  = 37N + 12R(N) + scan(N) + output(N) + 13 + sum_j M_j.
```

Poiche' `M_j <= R(N)`, un upper bound indipendente dai valori e'

```text
PBS_max(N) = 37N + 25R(N) + scan(N) + output(N) + 13.
```

Le due formule sono implementate in [sorgente, L385-L442](../src/private_argmin.rs#L385-L442) e replicate dal validatore in [validator, L626-L723](../../../benchmark/fhe_digiface_validation.py#L626-L723).

### 8.3 Caso `N=127`

Per `N=127`:

- `R(127)=43`;
- estrazione: `20*127 = 2540`;
- selezione: `17*127 + 12*43 = 2675`;
- scan: 42 OR di gruppo + 53 PBS di prefisso + 127 LUT finali = 222;
- output: sette maschere da 64 indici, ciascuna da 21 PBS, + tre LUT di gruppo = 150;
- confronto: 13.

Con soglie uniformi tutte le tredici maschere sono costanti, quindi `sum M_j=0`:

```text
2540 + 2675 + 222 + 13 + 150 = 5600 PBS.
```

Con soglie arbitrarie, usando l'upper bound `13R(127)=559` per la selezione delle soglie:

```text
2540 + 2675 + 222 + (559+13) + 150 = 6159 PBS.
```

I valori sono fissati nei test di conteggio ([sorgente, L1786-L1808](../src/private_argmin.rs#L1786-L1808)). `6159` e' un upper bound value-independent; `5600` e' il conteggio esatto del caso uniforme corrente.

## 9. Audit locale del rumore

Il parameter set usato dal servizio e' `V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64` ([servizio, L38-L41](../src/bin/varco_demo.rs#L38-L41)); il core assume un massimo di cinque unita' nominali di rumore prima di un PBS ([sorgente, L31-L35](../src/private_argmin.rs#L31-L35)).

Assumendo che ogni uscita PBS sia un ciphertext fresco con una unita' nominale, gli ingressi composti hanno i seguenti massimi locali:

| Operazione | Contributi freschi | Bound locale |
|---|---|---:|
| OR radix-4 | fino a 4 Booleani | 4 |
| stato pari `-c-z+a` | candidato + zero + OR | 3 |
| test zero dispari `e+w*b` | stato codificato + bit | 4 |
| normalizzazione dispari `-e+z-a` | stato + zero + OR | **5** |
| winner scan | candidato + prefisso + max 2 locali | 4 |
| confronto ternario | stato + 2 Booleani | 3 |
| digit/output group | fino a 4 ciphertext freschi | 4 |

Il massimo locale e' dunque cinque, raggiunto dalla normalizzazione dei livelli dispari, coerente con il margine dichiarato nel sorgente ([sorgente, L1292-L1305](../src/private_argmin.rs#L1292-L1305)). Questo audit giustifica il fan-in algebrico del circuito; non e' da solo una prova statistica di correttezza end-to-end.

## 10. Cosa non dimostra il bound locale

Il core usa direttamente le primitive `core_crypto`, che non trasportano ne' fanno rispettare a runtime la metrica `NoiseLevel` dell'API shortint. Restano separati almeno tre problemi:

1. **Formazione del punteggio.** La moltiplicazione polinomiale pubblica per `-2t_i` combina e amplifica il rumore del GLWE prima dell'estrazione.
2. **Estrazione custom.** La sequenza residue/shift/keyswitch/PBS/correction e la sua composizione richiedono un'analisi quantitativa propria ([sorgente, L701-L755](../src/private_argmin.rs#L701-L755)).
3. **Decodifica finale.** I gruppi sono emessi a `Delta=2^55` e fino a tre ciphertext vengono sommati senza un ulteriore PBS. La probabilita' di errore di questa decodifica non segue automaticamente dal `log2_p_fail` nominale del parameter set.

Anche il servizio distingue esplicitamente la compatibilita' geometrica della chiave da una garanzia di failure probability per il circuito low-level composto ([servizio, L489-L491](../src/bin/varco_demo.rs#L489-L491)).

Pertanto sono lecite le seguenti conclusioni:

- gli invarianti logici sono esatti nel dominio e nel modello honest-input dichiarati;
- ogni combinazione interna auditata prima di un PBS usa al massimo cinque contributi nominali;
- i conteggi 5600 e 6159 derivano staticamente dal circuito.

Non e' invece ancora lecito presentare il parametro nominale TFHE-rs come bound end-to-end del sistema senza una derivazione dedicata o un bound conservativo per tutte le fasi sopra elencate. La suite da 632 query, una volta conclusa, fornira' evidenza sperimentale distinta e non sostituira' tale prova probabilistica.

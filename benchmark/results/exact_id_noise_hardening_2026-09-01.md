# Diagnosi e hardening del rumore nell'uscita exact-ID

> **Registro storico che culmina nella revisione bounded da 7.804 PBS.** I conteggi e le prove
> canoniche citate in questo file identificano quella revisione e non validano automaticamente
> revisioni successive del circuito.

> **Registro cronologico, con esito canonico della suite ampia aggiunto successivamente.** Le
> misure delle sezioni 1--5 appartengono a revisioni intermedie poi superate. La revisione finale
> mantiene il comparatore Booleano ma ha rimosso anche il selettore accoppiato e i riscalamenti non
> coperti dal budget conservativo; i suoi conteggi statici sono 3.934 PBS a N=64, 7.804 a N=127
> e 7.852 a N=128. Dopo la regressione mirata 48/48, la suite canonica post-fix ha concluso
> **632/632** query senza discrepanze o errori; l'esito e i suoi limiti sono nella sezione 10. Lo
> lo stato successivo e' in `../../README.md` e `../../status.md`; questo file conserva anche la
> cronologia tecnica.

Data: 1 settembre 2026; aggiornamento della suite completa: 2 settembre 2026, ora locale. Questo
report separa deliberatamente i run diagnostici abortiti dalle regressioni post-fix. Nessun
denominatore viene aggregato alla validazione biometrica primaria.

## 1. Somma finale di N ciphertext: run diagnostico abortito

La prima suite ampia sul core exact-ID sommava N output PBS, uno per ogni identita'. Anche i
ciphertext con plaintext zero contribuivano rumore alla decodifica del singolo codice finale.
Il run e' stato fermato dopo 180 query, con due divergenze e zero errori operativi:

| sequenza zero-based | probe | atteso clear | osservato FHE |
|---:|---:|---|---|
| 118 | 113, genuine | indice 113, codice 114 | indice 112, codice 113 |
| 152 | 647, primary-test impostor | rifiuto, codice 0 | indice 0, codice 1 |

Non erano casi di frontiera. Il probe 113 aveva minimo -242 sul template 113, runner-up 278 sul
template 125 e gap 520; il probe 647 aveva minimo 216, cioe' 212 punti sopra `T=4`. Il pattern
`114 -> 113` e `0 -> 1` era coerente con un errore di decodifica dello scalare finale.

La correzione ricostruisce il codice sui suoi bit pubblici: ciascun bit OR-riduce gli indicatori
one-hot pertinenti, poi un PBS combina il bit con `global_accept` ed emette direttamente il suo
peso a `Delta=2^55`. La somma finale passa da N componenti fresche a 7 per N=127 e 8 per N=128.

Regressione intermedia, prima del fix successivo: otto cifrature fresche del probe 113 e otto del
probe 647, **16/16 corrette**, zero discrepanze e zero errori. Artefatti:

- `fhe_digiface_exact_output_bitwise_targeted_final_2026-09-01.csv`
- `fhe_digiface_exact_output_bitwise_targeted_final_2026-09-01.json`

Questa regressione isolava l'encoding di uscita; non certificava ancora l'intero circuito.

## 2. Somma nella selezione della soglia: secondo run diagnostico abortito

La suite ampia successiva ha trovato la prima divergenza entro 80 query e ne riportava tre a
90/632, sempre senza errori operativi, prima dell'interruzione diagnostica. Il caso isolato e':

| sequenza zero-based | probe | atteso clear | osservato FHE |
|---:|---:|---|---|
| 78 | 73, genuine | indice 73, codice 74 | rifiuto, codice 0 |

Anche questo caso era lontano dai confini: minimo -223, runner-up 240, gap 463 e margine 227 da
`T=4`. L'encoding dell'ID non spiegava un rifiuto tutto zero. L'ispezione ha individuato un'altra
somma larga: ciascun bit della soglia privata veniva ottenuto sommando tutti i winner indicator
abilitati da quel bit pubblico, fino a N ciphertext rumorosi.

Il secondo circuito intermedio usava invece 14 masked OR reduction di dimensione fissa N: 12 bit
della soglia traslata, sentinel `below` e sentinel `above`. Ogni livello aveva fan-in massimo 8 e
applicava un PBS di refresh. Il costo di quella revisione era 5.128 PBS a N=127 e 5.158 a N=128.

## 3. Regressione mirata dopo i primi due fix

Il validator ha eseguito, con chiavi temporanee fresche, otto cifrature di ciascuno dei tre probe
noti 113, 647 e 73:

- **24/24** risultati uguali all'oracolo clear;
- zero discrepanze e zero errori operativi;
- 24/24 probe ciphertext distinti;
- un solo LWE di 16.464 byte per risultato;
- 5.128 PBS per query.

Artefatti:

- `fhe_digiface_exact_threshold_refresh_targeted_2026-09-01.csv`
  (`sha256 26da8edcf7434f42d9f0c82d34db79d89218f6275ea987f2609e37a6e0e43548`)
- `fhe_digiface_exact_threshold_refresh_targeted_2026-09-01.json`
  (`sha256 e604c405a3ff4349c3e806871ad919ffaca881baca263bbd59392100273f99fa`)

Il JSON registra `success=true`, i fingerprint di sorgente/binario/cache/config, l'eseguibile
legato al PID, la chiave fresca e l'immutabilita' di tutti gli input durante il run.

Gli estremi `0/127` e `0/128` di quella revisione intermedia sono verificati separatamente in
`exact_id_refreshed_edges_2026-09-01.md`.

## 4. Stato ternario pesato della soglia: terzo run diagnostico abortito

La terza suite ampia, con stem `fhe_digiface_exact_primary_refreshed_2026-09-01`, e' stata
interrotta al progresso 50/632 dopo due nuove divergenze. I dati seguenti provengono dal log live:
il run abortito non ha prodotto CSV o JSON formali e non va contato come artefatto di validazione.

| sequenza zero-based | probe | atteso clear | osservato FHE | minimo / runner-up | margine da T=4 |
|---:|---:|---|---|---:|---:|
| 42 | 37, genuine | indice 37, codice 38 | rifiuto, codice 0 | -225 / 122 | 229 |
| 46 | 41, genuine | indice 41, codice 42 | rifiuto, codice 0 | -256 / 275 | 260 |

Neppure questi erano casi di frontiera: i gap fra vincitore e runner-up erano rispettivamente 347
e 531. La diagnosi viene dall'ispezione del codice e del suo budget di rumore, non da checkpoint
intermedi decrittati e conservati. Il comparatore della soglia codificava in un solo PBS lo stato
ternario e due bit come

```text
state + 4*any_zero + 8*threshold_bit
```

Il livello di rumore conservativo dell'ingresso arrivava quindi a 13, oltre il `max_noise_level=5`
del parameter set. Questo spiegava strutturalmente perche' il refresh della selezione della soglia
non bastasse a rendere affidabile il confronto finale.

Il terzo hardening sostituisce quello stato pesato con un comparatore Booleano MSB-first. Ponendo
`z=any_zero=!min_bit` e `t=threshold_bit`, per ogni bit calcola:

```text
same       = XOR(z, t)
new_equal  = AND(equal, same)
new_less   = OR(less, AND3(equal, z, t))
```

Alla fine `OR(less,equal)` implementa l'inclusivo `min<=threshold`; i sentinel applicano
`OR(above, AND(base, NOT below))`. Ogni gate non lineare applica un PBS di refresh e riceve una
somma non pesata di al massimo tre Booleani. Il costo cresce di 38 PBS: 5.166 a N=127 e 5.196 a
N=128.

## 5. Regressione mirata storica del comparatore Booleano

Con chiavi temporanee fresche, il validator ha eseguito otto cifrature di ciascuno dei cinque probe
113, 647, 73, 37 e 41:

- **40/40** risultati uguali all'oracolo clear;
- zero discrepanze e zero errori operativi;
- 40/40 probe ciphertext distinti;
- un solo LWE di 16.464 byte per risultato;
- 5.166 PBS per query.

Artefatti:

- `fhe_digiface_exact_boolean_comparator_targeted_2026-09-01.csv`
  (`sha256 84b159c62aeaaa843a90c9887154cffc4ed2f3614462d16cc6a7d02398a4e93c`)
- `fhe_digiface_exact_boolean_comparator_targeted_2026-09-01.json`
  (`sha256 9ddf02bc7e902128ff43f91146e51c30f51c830362a67c2a44f7f89cf6ab2f64`)

Il JSON registra `success=true`, zero modifiche agli input durante il run e il core
`sha256 91d3470dc089f277000d4f78047a9a96d29351c0ed0025c9c177c2684b9e5862`. Gli estremi del codice
corrispondente sono in `exact_id_boolean_comparator_edges_2026-09-01.md`. Il risultato 40/40 resta
valido per quella revisione a 5.166 PBS, ma non valida il core successivo descritto sotto.

## 6. Quarto fallimento osservato sul circuito a 5.166 PBS

La successiva suite ampia e' arrivata al progresso 100/632 e ha preservato 103 output prima
dell'interruzione diagnostica. Ha osservato una sola divergenza:

| sequenza zero-based | suite / probe | atteso clear | osservato FHE | minimo / runner-up | margine da T=4 |
|---:|---|---|---|---:|---:|
| 92 | `primary_genuine`, probe 87 | indice 87, codice 88 | rifiuto, codice 0, indice nullo | -269 / 208 (gap 477) | 273 |

Anche questo caso era lontano sia dal pareggio sia dalla soglia. Il ciphertext della query, le
chiavi e il binario originali sono stati preservati. In un nuovo processo dello stesso binario,
lo stesso ciphertext ha prodotto correttamente il codice 88; altre 16 esecuzioni dello stesso
ciphertext nello stesso processo sono state tutte corrette e bit-identiche. Anche una prima
esecuzione diagnostica con checkpoint ha restituito 88. Il fallimento fisico originale resta
quindi osservato ma non riprodotto, e non gli si attribuisce una causa precisa ex post.

## 7. Trace interno e rimozione del selettore accoppiato

Per localizzare gli stadi fragili e' stato aggiunto un percorso diagnostico locale che decritta
checkpoint interni senza cambiare l'output HTTP di produzione. Dopo i primi interventi
conservativi -- OR con fan-in massimo 4, refresh esplicito del winner e ricostruzione finale per
nibble -- ma prima della rimozione del selettore accoppiato, una trace perturbata ha mostrato una
divergenza riproducibile al bit 3 del punteggio. Per la coppia 43, cioe' i template 86/87,
`zero_candidate` era atteso 0 ma veniva decrittato come 1; di conseguenza `any_zero` passava da 0
a 1, il candidato corretto 87 veniva eliminato e l'uscita finale diventava 0.

Questa trace dimostra che la costruzione accoppiata era insicura nel run tracciato e individua il
primo checkpoint divergente. **Non dimostra che la stessa perturbazione fisica abbia causato il
fallimento one-shot originale**, che non si e' riprodotto con binario, chiavi e ciphertext
preservati. Per eliminare comunque il percorso non giustificato sono stati rimossi sia tutti i
packing a coppie del selettore sia il relativo aggiornamento pesato: ogni candidato segue ora un
percorso Booleano indipendente e rinfrescato.

## 8. Audit conservativo finale: bridge e nibble basso

Un audit successivo del budget ha trovato altri due percorsi che non rispettavano il limite
conservativo adottato, anche senza una nuova divergenza osservata:

- il bridge dei bit di score `b3..b7` usava moltiplicatori pubblici rispettivamente 32, 16, 8, 4
  e 2, amplificando anche il rumore. Ora questi bit sono ricodificati direttamente dalle uscite
  small-LWE dell'estrazione mediante PBS Booleani freschi, come gia' avveniva per il bit alto;
- il nibble basso del codice finale veniva emesso a una scala che richiedeva un fattore 16 prima
  del refresh di gruppo. Ora i bit bassi sono emessi direttamente a `BOOL_DELTA_LOG`, senza il
  riscalamento per 16; i gruppi vengono rinfrescati separatamente e l'uscita somma al massimo due
  componenti fresche.

Il core conserva inoltre OR a fan-in massimo 4, winner rinfrescati e comparatore Booleano. I
conteggi statici post-audit sono 3.934 PBS a N=64, 7.804 a N=127 e 7.852 a N=128. Una trace completa
sul ciphertext preservato del probe 87 ha attraversato tutti i checkpoint senza divergenze e ha
restituito correttamente il codice 88 a 7.804 PBS. E' evidenza diagnostica di quel caso, non una
validazione della suite ne' un bound formale del `p-fail` composto.

## 9. Regressione mirata post-fix: 48/48; suite completa allora pendente

La regressione post-fix pianificata contiene sei probe (`113`, `647`, `73`, `37`, `41`, `87`) con
otto cifrature ciascuno, per 48 query. Ha concluso **48/48** risultati uguali all'oracolo clear:
40 aperture con identita' esatta, 8 rifiuti corretti, zero discrepanze e zero errori operativi.
Tutte le 48 cifrature del probe hanno SHA-256 distinti e tutte le query riportano 7.804 PBS e il
contratto `exact-open-set-id-v2`. Il report evidence-grade e' in
`fhe_digiface_exact_noise_bounded_targeted_2026-09-01.md`, con CSV e JSON omonimi.

Questa regressione mirata blocca i sei casi scelti, compreso il probe 87, sul core post-audit. La
suite completa da 632 query non era ancora iniziata al momento di quella regressione; e' stata poi
eseguita come gate separato con l'esito riportato nella sezione seguente.

## 10. Suite canonica completa post-fix: 632/632

Il run canonico `--primary-suite` ha concluso tutte le **632/632** query pianificate. E' terminato
alle 00:06 del 2 settembre 2026 in ora italiana, anche se lo stem degli artefatti conserva la data
di avvio `2026-09-01`. La composizione era: 5 probe storici di frontiera, 127 genuine primari e
500 impostori primary-test, una cifratura per probe sotto una sola coppia di chiavi temporanee
fresca.

Risultato registrato dal JSON:

- **632/632 codici exact-ID uguali all'oracolo clear**;
- zero discrepanze e zero errori operativi;
- 131 aperture attese e 131 osservate;
- 632/632 probe ciphertext distinti per SHA-256;
- 7.804 PBS e contratto `exact-open-set-id-v2` in tutte le query;
- 127/127 genuine accettati con identificazione esatta; fra i 500 impostori primary-test, l'unica
  apertura chiara prevista e' stata riprodotta esattamente da FHE.

Artefatti canonici:

| artefatto | SHA-256 |
|---|---|
| [`fhe_digiface_exact_primary_noise_bounded_2026-09-01.csv`](fhe_digiface_exact_primary_noise_bounded_2026-09-01.csv) | `804aa4390ad00deed08698905540e458176bfd91db0618bd826baa93edebb80b` |
| [`fhe_digiface_exact_primary_noise_bounded_2026-09-01.json`](fhe_digiface_exact_primary_noise_bounded_2026-09-01.json) | `b6e54b92bef8f53c0ce057f1e68e9b473487fdd423776962579661669d4fa512` |

Il JSON vincola il run al core SHA-256
`61200a3d97626d4617b50cdb3101909e634ae597788fe05bb4d73f422b8abc8b`, al binario release
`f016349d45b6c90243a858373ac339c249074c3e63a62abc5e0e2019cd5689f3` e conferma che gli input
registrati sono rimasti invariati durante l'esecuzione.

E' una validazione funzionale empirica ampia della galleria e delle coorti pianificate, non una
prova formale: usa una sola chiave temporanea, una sola galleria DigiFace e soglia uniforme `T=4`.
In particolare, 632 successi osservati non derivano un bound della probabilita' di fallimento
dell'intero circuito da 7.804 PBS.

## Limite della conclusione

Le correzioni rimuovono percorsi di rumore osservati o non giustificati dall'audit conservativo;
non trasformano il valore nominale `log2_p_fail` del parameter set in un bound del circuito
composto. Le regressioni mirate storiche bloccano soltanto i fallimenti allora conosciuti, la
trace completa copre un solo ciphertext preservato e la nuova regressione 48/48 usa sei probe
selezionati sotto una singola coppia di chiavi. La validazione completa post-fix resta un artefatto
separato e ha superato tutte le 632 query pianificate senza divergenze; rafforza l'evidenza
funzionale ma non certifica la coda di errore del circuito composto.

# Bound deterministico del punteggio iniziale A38

Data: 2026-09-02. Perimetro: cifratura GLWE valida del probe, prodotto per il template in chiaro
ed estrazione dei due coefficienti di score. Il bound termina prima di KS, PBS, modulus switch e
FFT.

## Esito

Il rumore iniziale del punteggio non richiede un'ipotesi Gaussiana. TUniform(17) ha supporto
finito `[-2^17, 2^17]`; combinandolo con i vincoli che il core applica davvero alla galleria si
ottiene:

```text
massimo ||g||_2^2 ammesso dal dominio = 1022
massimo ||g||_1 esatto                = 682
massimo |errore score|                = 2 * 682 * 2^17
                                      = 178782208 unita' torus
```

Il bound e' molto inferiore ai raggi di decode delle due viste:

| vista | scala | raggio | raggio / massimo errore | slack log2 |
|---|---:|---:|---:|---:|
| score completo | `2^52` | `2^51` | 12.595.212,01 | 23,586 bit |
| score modulo 16 | `2^60` | `2^59` | 3.224.374.275,00 | 31,586 bit |

Quindi, sotto il contratto di input valido e client onesto, il supporto del rumore iniziale non
puo' attraversare un confine di decodifica. Il relativo termine di fallimento e' esattamente zero,
non una stima ottenuta da zero errori osservati.

Questo risultato restringe il blocco formale residuo: non e' piu' necessario lasciare un generico
`epsilon_score`. Restano da giustificare il key switch e la PBS di ogni selezione dell'estrattore,
le correzioni correlate sottratte al residuo e il classificatore A34-top.

## Derivazione dei vincoli

Per un template di norma quadratica `s`, il core costruisce il dominio Cauchy inclusivo

```text
[s - 2*ceil(sqrt(1024*s)), s + 2*ceil(sqrt(1024*s))]
```

di larghezza `4*ceil(sqrt(1024*s))+1`. Il massimo globale e' 4096; poiche' il dominio globale
contiene quello di ogni singolo template:

```text
s=1022 -> larghezza 4093, ammessa
s=1023 -> larghezza 4097, rifiutata
```

Con 512 coordinate in `[-3,3]` e budget quadratico 1022, l'ottimo intero della norma L1 usa 342
coordinate di valore assoluto 1 e 170 di valore assoluto 2:

```text
342*1^2 + 170*2^2 = 1022
342*1   + 170*2   = 682
```

Partendo da 512 valori assoluti unitari, ogni upgrade `1 -> 2` costa tre unita' di norma
quadratica e aggiunge una unita' L1; un upgrade `2 -> 3` costa cinque per lo stesso guadagno.
Pertanto `floor((1022-512)/3)=170` upgrade `1 -> 2` sono ottimali. Lo script verifica inoltre
l'ottimo per enumerazione intera dei conteggi `|g_i| in {0,1,2,3}`.

Per il coefficiente di score, il polinomio pubblico ha pesi `-2*g_i`. Ogni coefficiente d'errore
del GLWE appartiene a `[-2^17,2^17]`, dunque per disuguaglianza triangolare:

\[
|E_0| \leq 2\lVert g\rVert_1 2^{17} \leq 178782208.
\]

La vista completa usa i coefficienti d'errore `0..511`; la vista modulo 16 usa `1024..1535`.
Gli insiemi sono disgiunti e i coefficienti estratti 511 e 1535 non richiedono wrap
negaciclico. La disgiunzione e' utile per la provenance, ma il bound di supporto non richiede
indipendenza.

## Confine di fiducia

Il termine zero vale solo se il ciphertext e' stato prodotto dall'algoritmo di cifratura previsto
con TUniform(17) e il probe rispetta il contratto. Il server verifica forma e modulo del GLWE, ma
non possiede una prova crittografica che un client ostile abbia cifrato correttamente o che le due
lane contengano lo stesso probe. Questa e' una questione separata di validita' dell'input; non va
confusa con il p-fail del calcolo su input ben formato.

## Artefatti

- `benchmark/a38_initial_score_bound.py`
- `tests/test_a38_initial_score_bound.py`

Verifica:

```text
python3 -m unittest tests.test_a38_initial_score_bound tests.test_exact_id_pfail_certificate
.............
Ran 13 tests
OK
```


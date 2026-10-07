# Materiali di terzi e condizioni di riuso

Questa repository accompagna una ricerca. Al 6 ottobre 2026 non è stata
assegnata una licenza generale al codice e ai testi originali del progetto.
Le licenze dei componenti elencati sotto riguardano quei componenti e non
si estendono automaticamente agli altri materiali della repository.

## Codice copiato o adattato

| Materiale | Origine e condizioni |
|---|---|
| [`_adaface_net.py`](experiments/08_cnn/_adaface_net.py) | AdaFace di Minchul Kim; [licenza MIT](experiments/08_cnn/LICENSE.AdaFace-MIT), copyright 2022 Minchul Kim. La copia è identica a `net.py` della revisione upstream indicata sotto. |
| Estrazione TFHE adattata, nei pacchetti sperimentali e nel runtime | [BSD-3-Clause-Clear di TFHE-rs](experiments/14_pipeline_tfhe_rs/LICENSE.tfhe-rs-BSD-3-Clause-Clear). Le attribuzioni puntuali sono conservate nei sorgenti. |
| Codice RevHomTrace del [pacchetto Tetris](experiments/25_tetris/README.md) | [Licenza MIT di Kang Hoon Lee](experiments/25_tetris/runtime/LICENSE-RevHomTrace), copyright 2025. |
| Codice di confronto conservato in A117 | [Licenza MIT di COSIC-KU Leuven](experiments/attempts-a/a117/LICENSE.comparison-MIT), copyright 2021. |

Il confronto AdaFace del 6 ottobre 2026 usa la revisione upstream
[`c60eaa786a42c03444f3df7096dbaf9d57ae010d`](https://github.com/mk-minchul/AdaFace/tree/c60eaa786a42c03444f3df7096dbaf9d57ae010d).
SHA-256 del sorgente incluso: `b4db4eb0174a385fd29e5f616391b50d443f455990c8b88dcab1f8021af8ba4c`;
della licenza inclusa: `95b6e493eb9dba27f2150304e790ae254bab18d1611f4d6e2ade28fa3a271583`.
La corrispondenza identifica il contenuto verificato; non ricostruisce la
data o il commit del download originario.

Le librerie installate tramite Cargo e Python conservano le proprie licenze.
I lockfile identificano le versioni usate; questa pagina non sostituisce
le condizioni distribuite con ciascuna dipendenza.

## Pesi, dataset e fotografie

I pesi dei modelli e i dataset biometrici sono esterni e non vengono inclusi
con il codice. Per InsightFace, la [pagina ufficiale delle licenze](https://github.com/deepinsight/insightface#license)
distingue il codice MIT dai pesi preaddestrati, destinati alla ricerca non
commerciale. L'avvio della demo non attribuisce diritti aggiuntivi sui pesi.
Per AdaFace/CVLface e per ciascun dataset consultare le condizioni della
specifica distribuzione prima di scaricare, usare o redistribuire i dati.

Le fotografie pubbliche della demo hanno attribuzioni e condizioni per
singolo file nel [catalogo della galleria](demo/web/gallery/README.md).
Queste condizioni sono separate sia da quelle del codice sia da quelle
dei modelli biometrici. Foto personali, pesi e chiavi non fanno parte
dei materiali da pubblicare.

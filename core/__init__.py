"""core: motore condiviso del progetto.

Una sola fonte di verità per ciò che vale su più gradini della scaletta:
- `matching`  i circuiti FHE (la matematica cifrata): server e benchmark li
              importano da qui, così non possono divergere;
- `server` / `client`  il plumbing FHE (chiavi, serializzazione, run), indipendente
              dalla tecnica di embedding;
- `quantize`  float -> interi con segno (la FHE lavora su interi);
- `dataset`   caricamento e split dei dataset di volti;
- `metriche`  le metriche 1:N open-set (DIR@FPIR): i benchmark la importano da qui,
              così la metrica della tesi non può divergere tra script.

Ciò che cambia da un gradino all'altro (PCA, CNN, …) è solo l'embedding e vive nel
gradino, non qui.
"""

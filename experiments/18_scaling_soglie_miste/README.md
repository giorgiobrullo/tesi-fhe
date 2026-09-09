# 18 — Scaling, tre cifre ID e soglie miste

La baseline Head/PFKS viene estesa a dimensioni diverse, soglie uniformi
generali e soglie associate al vincitore. Il contratto sceglie prima il primo
minimo, poi verifica soltanto la sua soglia inclusiva: se non passa restituisce 0.

I sorgenti mantengono le cartelle sorelle originali sotto [source](source):
`fast-core-scaling-20260906`, `fast-core-uniform-20260906`,
`fast-core-wide-id-20260906` e `fast-core-mixed-20260906`. Ogni runner è nel
proprio `candidate/Cargo.toml`. Sono copiati anche i controlli A 126 e R 3
richiesti dai path locali, e i loro fixture pubblici deterministici incorporati
nel sorgente. I file `.u 64 le` inclusi sono corpi LUT pubblici, non cifrati.

[Risultati](RESULTS.json): scaling su tre chiavi fino aN 224, con A 126 invariato
solo alle taglie condivise fino aN 128; pilot separato fino aN 1024 contro A 126_3
adattato; gate distinti per soglie generali, ID larghi e soglie miste.
A N 127 le mediane M/A 126 sono 3,031/6,115 s. Il pilot N 1024 osserva 23,451/49,062 s
su una sola chiave. Sono confronti di core, non tempi della demo.

Capacità rappresentativa 3374, correttezza empirica del core fino a 1024 e
controlli HTTP storici fino a 225 non sono la stessa prova. Non si sommano
le percentuali delle taglie o dei gate. Restano carico esterno e limiti sulla
probabilità globale di errore e sull'accuratezza biometrica.

**Nessuna build o prova è stata eseguita nella nuova posizione.**
[PROVENANCE.json](PROVENANCE.json) registra le copie e i riepiloghi derivati;
le grandi evidenze cifrate rimangono negli originali locali. Nessuna chiave,
immagine, modello, ciphertext o target compiler è copiato.

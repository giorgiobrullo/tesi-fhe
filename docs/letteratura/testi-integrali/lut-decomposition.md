# Decomporre LUT grandi con PBS ordinari

[Primitive](../primitive-e-codesign.md) · [Letture integrali](README.md)

Sonia Belaïd, Nicolas Bon e Matthieu Rivain,
*Decomposition of Large Look-Up Tables for Fast Homomorphic Evaluation*,
[TCHES 2026(3), pp. 247–278](https://doi.org/10.46586/tches.v2026.i3.247-278).
Metadati editoriali ed ePrint [2026/724](https://eprint.iacr.org/2026/724)
verificati sulla [pagina autore](https://www.nicolasbon.com/) il 2 ottobre 2026.

**Versione letta:** [PDF autore](https://www.nicolasbon.com/assets/pdf/26HLUT.pdf),
32 pagine numerate 1–32, con CreationDate del 14 aprile 2026.
Questo campo descrive il file, non la data editoriale o una revisione certificata.
SHA-256: `cc45b49e20958f5c3fc1e327d84d1549d7fef08bdb4ba973dac75fd3a67efeb4`.
Non è stata verificata l'identità con il PDF finale TCHES.

## Costruzione

Una LUT su più cifre viene rappresentata mediante combinazioni lineari,
piccole funzioni non lineari e prodotti in un campo primo. Questi prodotti
richiedono due PBS ordinari; la decomposizione di una singola uscita usa
una catena di `λ` PBS e `t` prodotti, per un costo interno di
`λ + 2t` PBS (§§3–4, pp. 5–18). I coefficienti si ricavano risolvendo
un sistema lineare prima della valutazione cifrata.

Il caso con più uscite riusa catena e prodotti intermedi (§5.1, pp. 18–24).
Il vantaggio richiede quindi di considerare insieme le uscite della stessa
funzione; la ricerca della decomposizione e il formato dei cifrati restano
parte del problema.

## Parametri e limiti del confronto

Il modello di costo considera sicurezza, probabilità d'errore, campo di
embedding e norme delle combinazioni lineari (pp. 17–18). Ridurre i PBS
non autorizza a conservare automaticamente i parametri di un altro circuito.

La figura 8 confronta LUT con uguale larghezza d'ingresso e d'uscita:
metodo proposto e TBM usano un errore dichiarato di `2^-40`, WoP-PBS
di `2^-13.9` (§6, pp. 26–27). La tabella 5 presenta anche `2^-128`,
ma stampa `s=3,5` nelle prime due intestazioni, mentre §6 distingue
`s=2,4,16` da `p=3,5,17` (p. 32). L'ambiguità va risolta prima
di riutilizzare quei parametri.

**Inferenza per la tesi:** precedente per LUT e riuso fra uscite. Un adattamento
richiede una funzione finita che conservi parità e soglia del vincitore,
conversioni esplicite e verifica del rumore composto. Non sono stati misurati
risparmi nella pipeline locale.

Letti algoritmi 1–5, modello dei parametri e valutazione; figura 8 e tabelle
4–5 controllate anche visivamente. Nessuna replica del codice o verifica
indipendente completa delle dimostrazioni.

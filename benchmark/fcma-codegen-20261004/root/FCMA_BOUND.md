# NeonFcma: bound locale condizionale degli stessi operandi

4 ottobre 2026. Algebra nuova del grafo pubblico pulp0.22.3. Nessun build, esecuzione, FFT valutata, chiave/payload o modello precedente. Il risultato non attesta l'ambiente FP, il dispatch effettivo o un guadagno di tempo.

## Grafo e premesse

Fonte primaria: registry `index.crates.io-1949cf8c6b5b557f/pulp-0.22.3/src/aarch64.rs`, SHA256 `428f60728d89512826a40714a4d63bf299d848430e5e1579a49d69f0fb505f29`. I wrapper `vcmlaq_0_f64` e `vcmlaq_90_f64` (`:7–55`) emettono FCMLA rotazione0 e90; il ramo Miri esplicita le corrispondenti FMA per componente. `NeonFcma::mul_add_c64s` (`:2069–2074`) usa90(0(c,a,b),a,b); `mul_c64s` (`:2101–2103`) richiama questo MAC con accumulatore zero. `c64s=f64x2` contiene un complesso (`:1455–1458`).

Per `a=a_R+i a_I`, `b=b_R+i b_I`, `c=c_R+i c_I`, l'ordine è:

\[
\begin{array}{ll}
t_R=\operatorname{FMA}(a_R,b_R,c_R),&
t_I=\operatorname{FMA}(a_R,b_I,c_I),\\
y_R=\operatorname{FMA}(a_I,-b_I,t_R),&
y_I=\operatorname{FMA}(a_I,b_R,t_I).
\end{array}
\]

First pone c=0. Questo è **parte reale di a prima, parte immaginaria dopo**: l'ordine è opposto a Neon. Non si asserisce uguaglianza bit per bit dei risultati.

Assumiamo binary64 RN tie-to-even, FMA correttamente arrotondata una sola volta per componente, underflow graduale senza FTZ/DAZ, operandi e risultati finiti senza overflow/invalid, segni e lane esatti. Sono premesse sull'esecuzione; il testo Miri e la presenza dell'istruzione non le certificano. Poniamo come reali esatti

\[
u=2^{-53},\quad\eta=2^{-1075},\quad
\rho=\sqrt2\eta,\quad\kappa=u(2+u),\quad d=(2+u)\rho.
\]

Eta è metà del minimo subnormal positivo, non una costante floating valutata. Per ogni rounding scalare ammesso \(|\operatorname{RN}(x)-x|\le u|x|+\eta\); sulle due componenti, Minkowski dà \(\|e\|_2\le u\|x\|_2+\rho\). La norma del complesso è il modulo.

## Derivazione autonoma dal nuovo ordine

Definiamo \(P=(a_Rb_R,a_Rb_I)\), \(Q=(-a_Ib_I,a_Ib_R)\). Allora \(P+Q=ab\), \(\|P\|_2=|a_R||b|\le|a||b|\). Non servono indipendenza o cancellazioni tra operandi.

Per First, la prima FCMLA produce \(P+e_P\), con \(\|e_P\|_2\le u\|P\|_2+\rho\); la seconda arrotonda \(ab+e_P\). Dunque

\[
\begin{aligned}
|\widehat{ab}-ab|
&\le u|ab|+u(1+u)\|P\|_2+(2+u)\rho\\
&\le\boxed{\kappa|a||b|+d}. \tag{1}
\end{aligned}
\]

Per MAC, la prima FCMLA produce \(c+P+e_I\), con \(\|e_I\|_2\le u\|c+P\|_2+\rho\); la seconda arrotonda \(ab+c+e_I\). Perciò

\[
\begin{aligned}
|\widehat{ab+c}-(ab+c)|
&\le u|ab+c|+u(1+u)\|c+P\|_2+(2+u)\rho\\
&\le\boxed{\kappa(|a||b|+|c|)+d}. \tag{2}
\end{aligned}
\]

I coefficienti proposti sono quindi validi sotto le premesse: emergono da P, non dall'importazione cieca della prova Neon con Q.

## Due termini ordinari e1024 frequenze

Se il caller ordinario23×1 usa questo backend per il suo First+un MAC, ogni output p=mask/body ha target esatto
\(Z^*_{p,j}=H_{0,p,j}\beta_{0,j}+H_{1,p,j}\beta_{1,j}\), con **gli stessi H conservati e beta effettivi** del caller. L'indice0 indica la prima riga realmente consumata. L'accumulatore del MAC è il First effettivo:
\(c=H_0\beta_0+e_0\), \(|e_0|\le\kappa A_0+d\), \(A_t=|H_t||\beta_t|\).
Usando \(|c|\le A_0+|e_0|\), (2) e triangolare danno

\[
|\widehat Z_{p,j}-Z^*_{p,j}|
\le\kappa(2+\kappa)A_{0,p,j}+\kappa A_{1,p,j}+(2+\kappa)d.
\]

Per \(B_{t,p}=\bigl(\sum_{j=0}^{1023}|H_{t,p,j}|^2|\beta_{t,j}|^2\bigr)^{1/2}\), Minkowski fornisce separatamente per ciascun output

\[
\boxed{\|\widehat Z_p-Z^*_p\|_2
\le\kappa(2+\kappa)B_{0,p}+\kappa B_{1,p}+32(2+\kappa)d.}
\]

Il32 è \(\sqrt{1024}\), senza un altro \(\sqrt2\) di deinterleaving. Questa geometria è quella del loop ordinario di `tfhe-1.8.1/.../fft64/crypto/ggsw.rs:508–579,650–675`; la nuova derivazione non seleziona automaticamente Fcma in quel caller. Il suo Arch aarch64 corrente ammette Neon/Scalar, non NeonFcma (`pulp/.../aarch64.rs:3363–3384`). Un caller nuovo deve legare esplicitamente backend, token feature e immagine.

Nessun cap di prodotto è istanziato. Restano altri canali: creazione/uso FFT, cast e storia della chiave, spettri dei digit, inverse sullo stesso accumulatore effettivo, torus/map, righe/noise/decomposizione, target, real lift e traiettoria BR. La coincidenza di questo majorant generico con quello Neon non dà risultati identici, un bound completo BR/FHE/0-ID o un guadagno prestazionale.

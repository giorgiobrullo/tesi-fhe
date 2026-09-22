# Servizio Linux

Questa guida serve a chi amministra un server Linux e vuole avviare la
[demo web](../README.md) automaticamente. L'applicazione e il motore FHE
rimangono locali al server; un proxy pubblica la pagina tramite HTTPS.
Foto, sessioni e verifiche seguono gli stessi vincoli della guida web.

## 1. Predisporre utente e directory

La [unit systemd](varco-demo.service), cioè la configurazione con cui Linux
avvia e arresta il servizio, usa questa disposizione:

| Percorso | Contenuto |
| --- | --- |
| `/opt/varco-demo/app` | Sorgenti della demo, runtime completo e galleria |
| `/opt/varco-demo/venv` | Ambiente Python 3.12 |
| `/opt/varco-demo/bin` | Il binario del runtime compilato su Linux |
| `/var/lib/varco-demo` | Home dell'utente di servizio, modelli, chiavi e log |

Creare l'utente di sistema `varco-demo`, senza login, con home
`/var/lib/varco-demo`. Questa directory appartiene all'utente e ha permessi
`0700`; codice, ambiente Python e binari sotto `/opt` appartengono a root.
I modelli vanno in `.insightface/models` nella home del servizio. Le foto
aggiunte dai visitatori restano nella memoria dell'applicazione.

## 2. Preparare Python e i modelli

Su Ubuntu 24.04 installare l'interprete di sistema Python 3.12:

```sh
sudo apt-get update
sudo apt-get install python3.12 python3.12-venv
```

Preparare l'ambiente indicato dalla unit con questo interprete e i soli
requisiti web, senza il bootstrap completo del progetto che include Concrete.
Durante la preparazione amministrativa del server, dalla directory dei
sorgenti e con permessi di scrittura su `/opt/varco-demo`:

```sh
uv venv --no-python-downloads --python /usr/bin/python3.12 /opt/varco-demo/venv
uv pip install --python /opt/varco-demo/venv/bin/python -r demo/web/requirements.txt
```

L'interprete deve restare accessibile all'utente `varco-demo`. La unit usa
`ProtectHome=true`: un ambiente che rimanda a un Python gestito da uv nella
home dell'amministratore non può funzionare in quel servizio. Il percorso
esplicito `/usr/bin/python3.12` evita questa dipendenza dalle home private.
La directory dell'ambiente deve essere nuova; agli aggiornamenti usare
quella esistente. Per preparare i modelli usare questo interprete con la
home dell'utente di servizio, seguendo la [guida web](../README.md).

## 3. Compilare il motore e generare le chiavi

Dopo la compilazione descritta nella [guida web](../README.md), generare
le chiavi attuali come utente del servizio:

```sh
sudo -u varco-demo env HOME=/var/lib/varco-demo RAYON_NUM_THREADS=16 \
  /opt/varco-demo/bin/varco_demo_composite_v9 keygen \
  /var/lib/varco-demo/keys-current
```

## 4. Configurare gli indirizzi HTTPS e le sessioni

In `/etc/varco-demo.env` impostare
l'indirizzo HTTPS effettivo, per esempio:

```ini
VARCO_WEB_PUBLIC_ORIGIN=https://demo.example.org
VARCO_WEB_MAX_SESSIONS=512
```

La capacità delle sessioni è configurabile fra 1 e 4096; 512 è il valore
predefinito. La coda mantiene otto posti e un solo calcolo alla volta.
Aumentare le sessioni non aumenta il parallelismo FHE. Il recupero delle
sessioni abbandonate e la scadenza sono descritti nella
[guida web](../README.md#sessioni-e-verifiche).

Per mantenere attivo anche un secondo indirizzo durante un cambio di dominio,
aggiungere `VARCO_WEB_ADDITIONAL_ORIGINS=https://altro.example.org`.
Sono ammessi più indirizzi HTTPS separati da virgole. Le richieste che
modificano dati devono avere un `Origin` corrispondente al proprio `Host`;
le letture API respingono origini esterne. La normale navigazione alla
pagina iniziale da un link esterno è ammessa. I cookie non sono condivisi
tra domini; il proxy deve conservare `Host` e l'eventuale `Origin`.

## 5. Avviare e verificare il servizio

Installare la unit in `/etc/systemd/system/varco-demo.service`, poi:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now varco-demo
sudo journalctl -u varco-demo -n 30 --no-pager
```

Il primo avvio prepara anche i 120 ritratti. Lo stato systemd «active» indica
che il processo è avviato: verificare nella pagina che il servizio sia pronto
prima di condividere il link. Il proxy HTTPS inoltra a
`http://127.0.0.1:8010`, conservando `Host` e `Origin`. La porta nativa 9010
rimane locale. Un riavvio termina tutte le sessioni dei visitatori.

La pagina riceve gli aggiornamenti tramite `/api/eventi` (SSE, una connessione
su cui il server invia i nuovi stati). Il proxy deve inoltrare i dati appena
arrivano, senza buffering, e mantenere aperta
la connessione tra i messaggi di mantenimento inviati ogni 15 secondi.
Il launcher chiude questi flussi prima di attendere la fine delle normali
richieste durante un arresto del servizio.

Per capire cosa calcola il motore e come interpretare un esito, vedere la
[guida illustrata al confronto](../../../docs/come-funziona-il-confronto.md).

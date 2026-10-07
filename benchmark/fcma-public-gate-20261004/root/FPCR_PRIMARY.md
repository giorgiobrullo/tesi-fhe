# FPCR: fonte Arm primaria e limite del controllo

Documento ufficiale Arm Architecture Registers, scaricato via terminale da https://documentation-service.arm.com/static/60df1943677cf7536a55ddef. PDF8935128B SHA256a6eca120622b9bbce6ba7b8991ed6f5dbb4c1a4af600f832420e352ef83b0570; receipt ARM_PRIMARY_FETCH.json. I due accessi web alle pagine HTML/PDF avevano fallito, il successivo GET terminale è riuscitoHTTP200.

FPCR nelle pagine stampate652,656–657; testo estratto righe43873–43917 e44126–44171. RMode[23:22]=00 sceglie il round-to-nearest; FZ[24] governa il trattamento dei subnormali, AH[1] seleziona il trattamento alternativo e FIZ[0] governa i subnormali in ingresso. Per il probe si richiede zero per questi campi e non si modifica il registro.

La fonte avverte che altri fattori possono influire sul flush degli ingressi. Il valore letto è quindi un controllo delle premesse dichiarate, non una certificazione universale della piattaforma. Il confronto razionale dei casi pubblici, inclusi subnormali, verifica soltanto quelle operazioni reali. Il contratto numerico completo/FPhistory rimane aperto.

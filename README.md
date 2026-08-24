# Progetto SDN: Topologia ad Anello e Politiche di Filtraggio

## Autore
Diego Banfi


## Setup

### Prerequisiti

Sono necessari:

- Docker.
- Kathara.
- Git.
- Un sistema compatibile con Docker e Kathara.


## Descrizione del Progetto
L'obiettivo di questo progetto è la modifica della topologia SDN fornita nel Lab 18, 
passando da una struttura lineare a una **topologia ad anello** mediante l'aggiunta di un terzo switch (s3).
Il progetto include l'implementazione di politiche di sicurezza (firewall) e l'instradamento di flussi specifici 
sull'anello, gestendo le problematiche legate ai loop di livello 2.

## Modifiche apportate
- **Topologia:** Inserito switch `s3` connesso a `s1` e `s2`.
- **Configurazione:** Aggiornato `lab.conf` e creato `s3.startup`.
- **Controller:** Modificato `ryu_campus.py` per:
  - Implementare il blocco del traffico tra [IP_SORGENTE] e [IP_DESTINAZIONE].
  - Forzare il routing del traffico [TIPO_TRAFFICO] attraverso il nuovo nodo `s3`.
    
### Struttura del progetto

La directory principale deve contenere il file `lab.conf`, i file `.startup`
e la directory `docker/` con il Dockerfile del controller:

```text
.
├── README.md
├── lab.conf
├── docker/
│   └── Dockerfile.sdn
├── controller/
├── s1.startup
├── s2.startup
├── s3.startup
├── r1.startup
├── h1.startup
├── h2.startup
├── h3.startup
└── ext1.startup
```

### Costruzione dell'immagine Docker

Dalla directory principale del progetto, eseguire:

```bash
docker build -t asdn/sdn -f docker/Dockerfile.sdn docker/
```

Il comando costruisce l'immagine `asdn/sdn`, utilizzata dal nodo
controller definito in `lab.conf`.

### Avvio della topologia

Dopo aver costruito l'immagine, avviare tutti i nodi con:

```bash
kathara lstart
```

Il comando avvia il controller Ryu, gli switch OpenFlow `s1`, `s2` e `s3`,
il router `r1` e gli host della topologia.

### Arresto della topologia

Per arrestare e rimuovere i nodi del laboratorio:

```bash
kathara lclean
```

### Verifica dei container

Per controllare i nodi attivi:

```bash
docker ps
```

Per accedere a un nodo:

```bash
kathara connect s1
```

Sostituire `s1` con il nome del nodo desiderato, ad esempio `h1`, `h2`,
`h3`, `r1` o `ext1`.

## Documentazione

La documentazione completa del progetto, inclusi la descrizione della topologia,
le modifiche effettuate, il funzionamento del controller Ryu e tutti i test
eseguiti, è disponibile nel PDF:

[Apri la documentazione completa](doc/PROGETTO_SDN.pdf)





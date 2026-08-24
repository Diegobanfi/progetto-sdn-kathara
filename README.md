# Progetto SDN: Topologia ad Anello e Politiche di Filtraggio

## Autore
Diego Banfi

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

## Test di Funzionamento
- [ ] Connettività di base (ping) tra tutti gli host.
- [ ] Verifica loop e gestione broadcast (ARP).
- [ ] Test firewall: blocco traffico proibito (curl/ping).
- [ ] Test instradamento: traceroute su percorso `s3`.

## Comandi utili
- Avvio lab: `kathara lstart`
- Dump flussi: `ovs-ofctl dump-flows s1`
- Pulizia: `kathara lclean`

---

## Conclusioni
*(Questa parte la scriverai alla fine, spiegando le lezioni apprese sui loop e sulle potenzialità di OpenFlow).*



-modific lab.conf
-agg s3.startup
-verfico se s3 è collegato al controller e rete funziona: kathara lstart,kathara connect s3,
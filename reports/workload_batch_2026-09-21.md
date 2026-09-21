# Raggruppamento delle scritture di controllo — 21 settembre 2026

La mediana dei record TLS in uscita durante il download scende da 128 a 120
(-6,25%). Compaiono record che raggruppano due celle, ma la distribuzione resta
diversa da C Tor (mediana 108 record nelle nuove prove). Il tempo mediano del
download resta circa 158 ms in questo banco prova. Il risultato giustifica il
batching limitato, senza dimostrare un miglioramento delle proprietà di anonimato.

## Modifica

Gli ACK SENDME e i messaggi END già presenti nella coda di un circuito vengono cifrati in ordine e inviati con una sola scrittura, fino a 16 celle fisse. Il writer non aggiunge un timer: se c’è un solo messaggio, lo invia subito. La coda resta limitata e il chiamante riceve conferma solo dopo la scrittura completa. Gli ACK per stream già ritirati vengono esclusi prima della cifratura.

In caso di cancellazione, una scrittura già accodata su un canale condiviso termina prima del DESTROY del circuito; gli altri circuiti restano utilizzabili. Un errore fisico di scrittura resta un errore del canale. Non sono cambiati il contenuto degli ACK autenticati, le finestre di flusso, la cifratura, il ClientHello o la politica di padding.

## Confronto ripetuto

Tre nuove coppie Veil/C Tor, con lo stesso strumento e la stessa configurazione del confronto precedente: cinque relay locali, unico servizio onion C Tor, client con stato nuovo, guard comune e Vanguards-Lite. Dopo il riscaldamento: 4 KiB, quattro richieste da 4 KiB separate da 250 ms, download da 2 MiB e 60 secondi di inattività. Ordine Veil/C Tor, C Tor/Veil, Veil/C Tor. Le 36 richieste misurate hanno verificato byte per byte tutte le risposte, senza ritentativi nelle fasi misurate.

Go: `go version go1.27.1 darwin/arm64`. C Tor 0.4.9.12 / OpenSSL 3.6.4, `macOS-15.7.7-arm64-arm-64bit`. Build di misura senza race detector, SHA-256 `335e6efb48870964fe8582b518f661120429fc0fcc2a6e2d40d434dfaa6715d3`.

Mediana e intervallo minimo–massimo su tre prove. Le colonne prima/dopo provengono da due avvii distinti della rete privata: sono un confronto descrittivo, non una prova statistica controllata di anonimato o velocità. La colonna C Tor è la nuova misura di riferimento.

| Misura | Veil prima | Veil dopo | C Tor, nuova misura |
| --- | ---: | ---: | ---: |
| Richiesta 4 KiB, ms | 15.85 (12.40–18.43) | 17.34 (14.35–19.42) | 16.69 (14.90–19.54) |
| Quattro richieste, ms (pause incluse) | 821.44 (814.07–833.54) | 829.02 (812.83–830.17) | 817.20 (810.97–821.58) |
| Download 2 MiB, ms | 157.73 (156.33–161.29) | 158.00 (149.71–159.65) | 212.00 (189.33–226.71) |
| Download: record TLS in uscita | 128 (128–128) | 120 (118–122) | 108 (106–115) |
| Download: byte TLS in uscita | 68 608 (68 608–68 608) | 68 432 (68 388–68 476) | 73 462 (73 308–73 778) |
| Download: byte TLS in ingresso | 2 195 040 (2 194 842–2 195 466) | 2 194 908 (2 194 438–2 195 422) | 2 195 084 (2 194 996–2 195 128) |
| Inattività 60 s: record in uscita | 9 (8–10) | 8 (8–10) | 19 (18–22) |
| Inattività 60 s: record in ingresso | 4 (3–4) | 3 (3–6) | 19 (18–20) |

I byte TLS comprendono l’intestazione di 5 byte per record; non includono TCP/IP. Uscita indica client → guard. Un solo canale verso il guard è rimasto aperto fino alla fine in tutte le sei prove; nessun nuovo canale è stato aperto nelle fasi misurate.

## Distribuzione delle dimensioni

Record cumulativi nelle tre fasi di download; dimensione del payload TLS, intestazione esclusa.

| Payload TLS, byte | Veil prima | Veil dopo | C Tor, nuova misura |
| --- | ---: | ---: | ---: |
| 531 | 384 | 336 | 254 |
| 1045 | 0 | 24 | 64 |
| 1559 | 0 | 0 | 11 |

## Singole prove

| Coppia | Client | Download, ms | Record download in uscita | Record inattività uscita/ingresso | Tentativi falliti nel riscaldamento |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | veil | 159.654 | 120 | 8/6 | 1 |
| 1 | c_tor | 212.001 | 108 | 22/18 | 0 |
| 2 | c_tor | 226.706 | 115 | 19/19 | 0 |
| 2 | veil | 149.711 | 118 | 8/3 | 0 |
| 3 | veil | 157.998 | 122 | 10/3 | 0 |
| 3 | c_tor | 189.333 | 106 | 18/20 | 0 |

## Limiti e passi successivi

Restano differenti il ClientHello e la gestione dell’inattività. I record cifrati durante l’inattività possono contenere manutenzione: non vengono classificati come puro padding. Il batching introdotto riguarda solo controlli già disponibili sullo stesso circuito, non i DATA e non l’intero scheduler di C Tor.

Sono misurati record TLS al completamento sul proxy locale, non pacchetti IP o celle Tor decifrate. Proxy, buffering, pianificazione del sistema e percorsi casuali nella piccola rete influenzano i risultati. Bootstrap e riscaldamento sono esclusi dalle tabelle; eventuali ritentativi modificano l’età dei circuiti. Le connessioni ancora aperte sono terminate dall’osservatore: la loro vita completa non è misurata.

Restano da verificare upload, inattività prolungata, guasti, rete pubblica e resistenza a un classificatore. Non segue una garanzia di anonimato o di indistinguibilità.

## Verifiche e dati

Suite completa `go test -race ./...`, test mirati del batching, `go vet ./...`, `go vet -tags veiltraffic ./...` e 7 test Python superati. Gosec: 68 file di produzione, zero rilievi, 19 annotazioni. I nuovi test verificano: validazione prima di scrivere, conferma solo a batch completo, errore su scrittura parziale, ordine prima del DESTROY, isolamento tra circuiti, limite del batch, filtro degli ACK ritirati e integrità/ordine crittografico con un peer indipendente.

Le metriche di ogni fase sono state ricalcolate dalle tracce e confrontate con il riepilogo; i byte applicativi sono identici fra i due client.

[Riepilogo JSON](workload_batch_2026-09-21.json) · [Metadati TLS completi, gzip](workload_batch_2026-09-21.traces.json.gz) · [Confronto precedente](workload_2026-09-21.md).

```sh
python3 scripts/compare_workload.py --tor /path/to/tor \
  --tor-gencert /path/to/tor-gencert \
  --report /tmp/veil-workload-batch.json --samples 3 --idle 60
```

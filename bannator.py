#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Autore: Vincenzo Argese @crisiumdevstudio
# YouTube: https://www.youtube.com/@crisiumdevstudio <-- Iscriviti e attiva la campanella GRAZIE
#
# Script: bannator.py
# Descrizione: Script Python – bloccare IP da attacchi brute force
# Data pubblicazione: 2 Aprile 2010 (Data di oggi 23 feb 2023 ...OMG)
#
# Web: www.vasystems.it
# Articolo: https://www.informaticawebsystems.com/guida-script-python-bloccare-indirizzi-ip-attacchi-brute-force/
# (Ex-Progetto) Progetto Elven.it WebTV: https://www.youtube.com/channel/UCf36btbKZPx8wTvIP6jKPaQ


# Importiamo la libreria string per gestire le righe dei file
import string

# In questa variabile inseriamo il percorso del file di log
pathlog = '/var/log/'

# Indichiamo in questa variabile il file di log su da verificare
filelog = 'auth.log'

# Specifichiamo il path file hosts.deny
pathban = '/etc/'
#
fileban = 'hosts.deny'

# Nella variabile target specifichiamo la stringa da utilizzare nella ricerca degli indirizzi IP
# che stanno tentando l'accesso nel nostro sistema. Sappiamo che i log sono presenti nel
# file /var/log/auth.log e la riga del log con l'accesso fallito e'
# Failed password for invalid user admin from 192.168.1.2 port 17727 ssh2
# Quindi prendiamo come riferimento la stringa 'Failed password'
#
target = 'Failed password'

# Numero di tentativi massimi consentiti da ogni IP per connettersi al server
# su cui e' in esecuzione questo script.
#
BANNA = 3

# Iniziamo a realizzare il codice vero e proprio:

# Contiamo il numero di caratteri della stringa contenuta in target, questo numero ci
# permettera' di gestire la stringa e identificare in modo assolutamente preciso l'IP da bloccare.
#
lunghezza = len(target)

# Apro il file auth.log in sola lettura (perche' devo semplicemente ricavare l'informazione
# sulle connessioni e sugli IP)
#
f = file(pathlog+filelog, 'r')

# Creiamo un dizionario python contenente gli IP bannati.
# Il dizionario e' una struttura che ci permette di gestire le informazioni per chiave e valore
# nel nostro caso useremo come chiave l'IP e come valore un numero intero che conta le volte
# che l'IP non riesce ad eseguire l'accesso.
# {key:valore, key2:valore2, …}
# es.: {'192.168.1.2': 2, '172.16.8.10': 3}
#
ip_bannati = {}

# Leggo la prima riga del file auth.log e copio il contenuto nella variabile i;
i = f.readline()

# Ciclo il file finche' la variabile i che contiene la riga da esaminare non e' vuota
# quindi finche' il file auth.log non e' terminato.
#
while (i != ""):
    # Tramite il metodo find di string ottengo la posizione della stringa in cui stato trovato il target
    #
    posizione = string.find(i,target)

    # Se la posizione e' diversa da -1 significa che il targhet e' stato trovato
    # Quindi la stringa letta contiene 'Failed password' ora dobbiamo riuscire a prendere
    # la parte della stringa che contiene l'IP
    if posizione != -1:
        # RICERCA IP
        # Concentriamoci sulla riga del file auth.log e in particolare alle parole tra cui l'IP
        # e' compreso: from 192.168.1.2 port
        #
        # Prima di identificare l'IP faccio la ricerca della stringa
        # from per assicurarmi la corretta posizione
        #
        inizio = string.find(i,"from")
        if inizio != -1 :
            inizio = inizio + 5 # +5 caratteri di from e spazio

            # Calcolo la posizione finale tramite la stringa port
            fine = string.find(i,"port")

            # Ottengo la substring con con l'IP da bannare
            ip = i[inizio:fine-1]

            # Se l'IP e' gia' presente in ip_bannati
            if ip in ip_bannati:
                # Aggiorna semplicemente il suo contatore
                ip_bannati[ip] = ip_bannati[ip] + 1
            else :
                # Altrimenti inserisci l'IP e imposta il suo contatore a 1
                ip_bannati[ip] = 1

        # A questo punto abbiamo finito il lavoro su una singola riga quindi procediamo
        # con la riga successiva del file auth.log e ed esaminiamola nuovamente con il ciclo while
        i = f.readline()

# In questo punto siamo usciti dal while, questo significa che il file auth.log e' terminato
# e non abbiamo altre righe da esaminare, quindi possiamo chiudere il file.
f.close()

# Creo una copia di backup del file hosts.deny perche' ogni volta che lancio lo script
# perdo gli IP bloccati precedentemente
denyold = file(pathban+fileban, 'r') # Apro hosts.deny in lettura
deny = file('_'+fileban, 'w') # Creo il file _hosts.deny di backup

# Leggo tutte le righe di hosts.deny e le copio in _hosts.deny
i = denyold.readline()
while (i!=""):
    deny.write(i)
    i = denyold.readline()

# Ora non resta che verificare quali IP hanno superato il numero
# massimo di tentativi consentiti e scriverli nel file _hosts.deny con la regola opportuna.
#
# Ciclo per verificare tutti gli IP inseriti nel dizionario
#
for i in ip_bannati :
    # Se l'IP ha superato il numero massimo di tentativi
    #
    if ip_bannati[i] > BANNA :
        # Scrivi nel file hosts.deny l'IP con la regola ALL = BLOCCA TUTTO
        # es.: ALL:192.168.1.10 e vai a capo.
        #
        deny.write('ALL:'+ i+'\n')

# Chiudo i file
denyold.close()
deny.close()

# Copio il contenuto di _hosts.deny nel file /etc/hosts.deny
deny = file(pathban+fileban, 'w')
denytmp = file('_'+fileban, 'r')
i = denytmp.readline()
while (i!=""):
    deny.write(i)
    i = denytmp.readline()

denytmp.close()
deny.close()
# Fine
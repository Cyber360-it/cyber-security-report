# Cyber Security Report

Report mensili di threat intelligence ransomware, con fonti, dati verificati e script di verifica **read-only**. Sono collegati alla rubrica *Cyber Security Report* pubblicata su LinkedIn.

Ogni mese il report analizza il gruppo ransomware più attivo sui leak site e le tecniche documentate da fonti affidabili (MITRE ATT&CK, vendor di threat intelligence). Questa repository trasforma quell'analisi in un controllo concreto che puoi eseguire sui tuoi sistemi Windows.

> **Un esito "VERIFY" non significa che il sistema sia vulnerabile.**
> Il sistema presenta configurazioni che meritano verifica rispetto alle tecniche osservate nel gruppo analizzato.

---

## Report disponibili

| Mese | Gruppo analizzato | Report | Script | Dati |
|---|---|---|---|---|
| Settembre 2026 | The Gentlemen | [Report](reports/2026-09-the-gentlemen/README.md) | [`Exposure-Check.ps1`](reports/2026-09-the-gentlemen/Exposure-Check.ps1) | [`chart-data.json`](reports/2026-09-the-gentlemen/chart-data.json) |

Ogni cartella mensile contiene: report con fonti e mapping MITRE ATT&CK, script di verifica, dati dei grafici in JSON e infografica.

---

## Garanzie dello script

- **Read-only**: legge registro, servizi e configurazioni. Non modifica nulla.
- **Locale**: non scansiona altri host o indirizzi IP.
- **Nessun dato inviato all'esterno**: nessuna connessione di rete. L'export CSV, se richiesto, resta sul disco locale.
- **Nessun exploit** e nessun download di componenti aggiuntivi.
- **Codice leggibile**: ogni controllo è commentato con la tecnica MITRE ATT&CK di riferimento.

---

## Come eseguirlo (passo per passo)

### 1. Scarica lo script

Dalla cartella del report del mese, clicca su **Exposure-Check.ps1** → pulsante **Download raw file**.

Oppure da PowerShell:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Cyber360-it/cyber-security-report/main/reports/2026-09-the-gentlemen/Exposure-Check.ps1" -OutFile ".\Exposure-Check.ps1"
```

### 2. Verifica l'integrità (consigliato)

Confronta l'hash con quello pubblicato in [`SHA256SUMS.txt`](SHA256SUMS.txt):

```powershell
Get-FileHash .\Exposure-Check.ps1 -Algorithm SHA256
```

### 3. Leggilo prima di eseguirlo

È un principio di base: non eseguire mai uno script scaricato da Internet senza averlo letto. Questo è stato scritto per essere letto in pochi minuti.

### 4. Sblocca il file

Windows marca i file scaricati da Internet. Dopo averlo letto:

```powershell
Unblock-File .\Exposure-Check.ps1
```

### 5. Esegui come amministratore

Apri PowerShell **come amministratore** (alcuni controlli richiedono privilegi elevati):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Exposure-Check.ps1
```

`-ExecutionPolicy Bypass` vale solo per questa esecuzione e non modifica la policy del sistema.

Per salvare i risultati in un CSV locale:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Exposure-Check.ps1 -CsvPath .\exposure-check.csv
```

Parametri opzionali:

| Parametro | Default | Significato |
|---|---|---|
| `-PatchAgeDays` | 45 | Giorni oltre i quali l'ultimo hotfix è considerato vecchio |
| `-MaxLocalAdmins` | 2 | Numero massimo atteso di membri del gruppo Administrators |
| `-CsvPath` | — | Percorso locale per l'export CSV |

### 6. Leggi i risultati

Ogni riga riporta `RunOn`, `Hostname`, area, controllo, valore rilevato, esito e tecnica ATT&CK collegata.

| Esito | Significato |
|---|---|
| `OK` | Configurazione coerente con le buone pratiche |
| `VERIFY` | Configurazione da verificare nel tuo contesto |
| `INVESTIGATE` | Indicatore da approfondire (es. driver noti per BYOVD) |
| `INFO` | Informazione utile, nessun punteggio |
| `UNKNOWN` | Non determinabile localmente: verificare manualmente |

---

## Exposure score

Lo score è **deterministico**: ogni condizione ha un peso fisso, documentato nel report del mese.

| Score | Livello |
|---|---|
| 0–19 | LOW |
| 20–49 | MEDIUM |
| 50+ | HIGH |

> **Questo score non predice la probabilità di un attacco. Evidenzia configurazioni che richiedono attenzione.**

---

## Requisiti

- Windows 10/11 o Windows Server 2016+
- Windows PowerShell 5.1 o PowerShell 7+
- Privilegi di amministratore locale (consigliati)

---

## Limiti

- Lo script verifica **un singolo host**. Non sostituisce un vulnerability assessment, un EDR o una revisione di Active Directory.
- Alcuni controlli (es. AV/EDR di terze parti su Windows Server) possono risultare `UNKNOWN`: in quel caso verifica dalla console del tuo prodotto.
- La ricerca dei driver BYOVD avviene per nome file: un file rinominato non viene rilevato.
- Su un domain controller il controllo degli amministratori locali non è applicabile.

---

## Disclaimer

Gli script sono forniti "così come sono", a scopo difensivo e informativo, senza garanzie. Eseguili prima in un ambiente di test e secondo le policy della tua organizzazione. L'autore non è responsabile di un uso improprio.

## Licenza

[MIT](LICENSE)

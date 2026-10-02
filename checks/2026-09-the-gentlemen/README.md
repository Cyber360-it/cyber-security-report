# Settembre 2026 — The Gentlemen

**Report:** Cyber Security Report — Settembre 2026
**Periodo analizzato:** rivendicazioni pubblicate sui leak site dall'1 al 30 settembre 2026
**Script:** [`Exposure-Check.ps1`](Exposure-Check.ps1)

## Contesto

A settembre 2026 ransomware.live ha registrato 788 organizzazioni pubblicate sui leak site da 76 gruppi. The Gentlemen ne ha rivendicate 102 (12,9%). 94 di queste sono state pubblicate in soli quattro giorni: un andamento a blocchi, tipico della pubblicazione di arretrati.

Dati: rivendicazioni pubblicate, **non attacchi confermati**.

## Tecniche documentate e controlli collegati

| Tecnica osservata | ATT&CK | Controllo nello script |
|---|---|---|
| Accesso via RDP, RDP abilitato tramite registro | T1021.001 | RDP abilitato, NLA, membri Remote Desktop Users |
| Movimento laterale via SMB / PsExec | T1021.002 | SMBv1 |
| Modifica del firewall con netsh | T1562.004 | Profili firewall disabilitati |
| Disattivazione Defender/EDR via GPO e registro | T1562.001 | Protezione AV/EDR attiva, Tamper Protection |
| BYOVD con driver firmati vulnerabili | T1562.001 / T1014 | Presenza di ThrottleBlood.sys, viragt64.sys |
| Sfruttamento di vulnerabilità | T1190 / T1068 | Età dell'ultimo hotfix |
| Uso di account validi e privilegiati | T1078 | Membri del gruppo Administrators |
| Remote management | T1021.006 | Servizio WinRM |
| LLMNR/NBT-NS poisoning e SMB relay | T1557.001 | LLMNR disabilitato via policy |
| Esecuzione PowerShell | T1059.001 | Script Block Logging |
| Persistenza con AnyDesk e strumenti RMM | T1219 | Servizi RMM/remote access installati |
| Furto credenziali Veeam, blocco ripristino | T1555 / T1490 | Presenza servizi Veeam |

## Pesi dello score

| Condizione | Punti |
|---|---|
| RDP abilitato | +10 |
| RDP senza NLA | +15 |
| SMBv1 abilitato | +20 |
| Almeno un profilo firewall disabilitato | +15 |
| Nessuna protezione AV/EDR real-time rilevata | +20 |
| Ultimo hotfix più vecchio della soglia (default 45 giorni) | +15 |
| Membri Administrators oltre la soglia (default 2) | +10 |
| WinRM in esecuzione | +5 |
| LLMNR non disabilitato | +5 |

Gli esiti `INFO`, `INVESTIGATE` e `UNKNOWN` valgono 0 punti.

0–19 LOW · 20–49 MEDIUM · 50+ HIGH

> Questo score non predice la probabilità di un attacco. Evidenzia configurazioni che richiedono attenzione.

## Controlli che lo script non può fare (ma che contano)

Le tecniche di questo gruppo coinvolgono componenti che non si verificano da un singolo endpoint:

- **FortiGate / VPN**: versione firmware aggiornata (CVE-2024-55591), MFA su ogni accesso VPN, interfaccia di amministrazione non esposta su Internet.
- **Active Directory**: chi può modificare le GPO; alert sulle modifiche a GPO e alla share NETLOGON.
- **NBT-NS**: va disattivato anche sulle schede di rete o via DHCP, non solo LLMNR.
- **Backup**: credenziali Veeam separate dal dominio, repository immutabile o offline.
- **VMware ESXi / vCenter**: patch (es. CVE-2024-37085), accesso amministrativo non legato ai gruppi AD.

## Fonti

- ransomware.live — https://www.ransomware.live
- Trend Micro — *Unmasking The Gentlemen Ransomware*
- Group-IB — *How Hastalamuerte Operates: Group-IB's Analysis of The Gentlemen's Attack Methods*
- MITRE ATT&CK — https://attack.mitre.org

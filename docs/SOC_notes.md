# Notes SOC - Méthodologie et concepts

## 📚 Introduction aux IOC

Les **Indicators of Compromise (IOC)** sont des artefacts observables sur un réseau ou système qui indiquent avec une haute probabilité une intrusion. Ce projet implémente les principaux types d'IOC utilisés dans un SOC.

## 🎯 Types d'IOC implémentés

### 1. Hash-based IOCs
- **MD5, SHA1, SHA256** : Empreintes de fichiers malveillants
- **Utilisation SOC** : Identification rapide de malware connus
- **Limitation** : Facilement contourné par polymorphisme

### 2. Network IOCs
- **Adresses IP** : Serveurs C2, sources d'attaques
- **Domaines** : Sites de phishing, domaines malveillants
- **URLs** : Chemins spécifiques d'exploitation

### 3. Behavioral IOCs
- **Processus suspects** : Chaîne de processus anormale
- **Commandes système** : Patterns d'exécution malveillants
- **Modifications registre** : Persistance, configuration

## 🔍 YARA vs IOC vs Sigma

### YARA
- **But** : Détection basée sur des patterns complexes
- **Avantages** : Flexible, puissant, supporte regex et conditions
- **Cas d'usage** : Malware hunting, classification de familles

### IOC simples
- **But** : Détection rapide d'indicateurs atomiques
- **Avantages** : Simple, rapide, facile à partager
- **Cas d'usage** : Blocage immédiat, première ligne de défense

### Sigma (non implémenté ici)
- **But** : Règles de détection pour logs SIEM
- **Avantages** : Portable entre SIEM, standardisé
- **Cas d'usage** : Détection comportementale dans les logs

## 🛠️ Configuration d'un lab local

### Option 1 : Machine virtuelle
```bash
# Installation VirtualBox + VM Ubuntu/Kali
# Cloner le repo dans la VM
# Créer des fichiers tests avec hash connus
echo "malware test" > test.txt
md5sum test.txt  # Ajouter ce hash aux IOC
```

### Option 2 : Docker isolé
```bash
# Créer un réseau isolé
docker network create --internal ioc-lab

# Lancer le scanner dans ce réseau
docker run --network ioc-lab mini-soc-ioc-lab
```

### Option 3 : WSL2 (Windows)
```powershell
# Installer WSL2
wsl --install

# Dans WSL
git clone https://github.com/yourusername/mini-soc-ioc-lab
python3 -m venv venv
source venv/bin/activate
```

## 📊 Workflow SOC avec ce projet

### 1. Collecte d'IOC
```
Threat Intel Feed → ioc_list.txt → Scanner
```

### 2. Détection
```
Scanner → Scan files/processes/logs → Matches IOCs → Generate alerts
```

### 3. Investigation
```
Alert → Contexte (OSINT) → Analyse → Décision
```

### 4. Response
```
Isolation → Remediation → Documentation → Update IOCs
```

## 🎓 Transformation en ticket d'incident

### Exemple de ticket SIEM/SOAR

```yaml
Incident:
  ID: INC-2025-0125-001
  Title: "Malware Detection - Trojan.Generic"
  Severity: HIGH

  Detection:
    Time: 2025-01-25 14:30:00 UTC
    Source: IOC Scanner
    Rule: HASH match + YARA Suspicious_PE

  Affected Assets:
    - Hostname: DESKTOP-ABC123
    - IP: 192.168.1.50
    - File: C:\Users\john\Downloads\invoice.exe
    - Hash: 44d88612fea8a8f36de82e1278abb02f

  Context:
    - VirusTotal: 45/70 detections
    - First seen: 2025-01-20
    - Associated campaign: Emotet

  Actions Required:
    - [ ] Isolate endpoint
    - [ ] Collect memory dump
    - [ ] Check lateral movement
    - [ ] Review proxy logs
    - [ ] Update EDR rules

  Playbook: MAL-001-TROJAN-RESPONSE
```

## 🔗 Intégration avec outils SOC

### SIEM Integration
```python
# Exemple d'envoi vers Splunk
import requests

def send_to_splunk(detection):
    splunk_hec = "https://splunk:8088/services/collector"
    headers = {"Authorization": "Splunk HEC_TOKEN"}

    event = {
        "time": detection['timestamp'],
        "source": "ioc_scanner",
        "sourcetype": "ioc:detection",
        "event": detection
    }

    requests.post(splunk_hec, json=event, headers=headers)
```

### EDR Response
```python
# Exemple d'isolation CrowdStrike
def isolate_host(hostname):
    # API call to CrowdStrike
    cs_api.hosts.isolate(hostname)

    # Log action
    logger.critical(f"Host {hostname} isolated due to IOC match")
```

## 📈 Métriques SOC

### KPIs mesurables avec ce projet

1. **Mean Time to Detect (MTTD)**
   - Temps entre compromission et détection
   - Objectif : < 1 heure

2. **False Positive Rate**
   - Ratio alertes fausses / total
   - Objectif : < 5%

3. **IOC Coverage**
   - % de menaces connues détectables
   - Objectif : > 95% pour APT connus

4. **Scan Performance**
   - Fichiers/seconde scannés
   - Objectif : > 1000 files/sec

## 🚀 Évolutions possibles

### Court terme
- Intégration API VirusTotal automatique
- Support de formats STIX/TAXII
- Dashboard web temps réel

### Moyen terme
- Machine Learning pour détection anomalies
- Intégration MISP (threat sharing)
- Sandbox automatique (Cuckoo)

### Long terme
- Orchestration SOAR complète
- Threat Hunting proactif
- AI-powered IOC generation

## 📖 Ressources d'apprentissage

### Certifications recommandées
- **CompTIA Security+** : Bases de la sécurité
- **CompTIA CySA+** : Analyse SOC
- **GIAC GSOC** : SOC analyst
- **Splunk Certified** : SIEM expertise

### Plateformes de pratique
- **TryHackMe** : SOC Level 1 & 2 paths
- **HackTheBox** : Forensics challenges
- **CyberDefenders** : Blue team labs
- **LetsDefend** : SOC simulator

### Outils complémentaires
- **MISP** : Threat intelligence sharing
- **TheHive** : Incident response platform
- **Cortex** : Observable analysis
- **OpenCTI** : Cyber threat intelligence

## 💡 Tips pour entretien SOC

### Questions techniques fréquentes
1. **"Qu'est-ce qu'un IOC ?"**
   - Réponse avec exemples concrets de ce projet

2. **"Comment investiguer une alerte ?"**
   - Montrer le workflow : Détection → Contexte → Analyse → Action

3. **"Différence entre IDS et IPS ?"**
   - IDS détecte (ce projet), IPS bloque

4. **"Qu'est-ce que MITRE ATT&CK ?"**
   - Framework de tactiques/techniques, mappable aux détections

### Démonstration pratique
```bash
# Pendant l'entretien, montrer :
1. Lancement du scan
2. Détection d'un IOC
3. Génération du rapport
4. Explication des actions à prendre
```

## 🏁 Conclusion

Ce projet démontre la capacité à :
- **Automatiser** la détection de menaces
- **Comprendre** les méthodologies SOC
- **Implémenter** des solutions opérationnelles
- **Documenter** clairement les processus
- **Évoluer** avec les besoins du SOC

---

*Ces notes complètent le projet technique en fournissant le contexte SOC nécessaire pour comprendre son utilité dans un environnement de production.*
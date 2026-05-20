# LAB14_SM - Contournement de la Détection Root avec Frida et Objection

## 📋 Table des Matières
- [Étape 1 - Vérification de Frida](#étape-1--vérification-de-frida)
- [Étape 2 - Injection du Script de Bypass](#étape-2--injection-du-script-de-bypass-root)
- [Étape 3 - Exploration avec Objection](#étape-3--exploration-avec-objection)
- [Récapitulatif des Hooks Actifs](#récapitulatif-des-hooks-actifs)
- [Conclusion](#conclusion)

---

## ✅ Étape 1 – Vérification de Frida

### Commande Exécutée
```bash
frida -U -f owasp.mstg.uncrackable1 -l hello.js
```

### Résultat
![Vérification Frida](https://github.com/user-attachments/assets/aaaa1f08-e4a1-4005-8426-8cf2e085b1f1)

### 🎯 Observation
- ✅ Le script `hello.js` s'injecte correctement
- ✅ `Java.perform` est exécuté avec succès
- ✅ L'environnement Frida est opérationnel

---

## 🚫 Étape 2 – Injection du Script de Bypass Root

### Commande Exécutée
```bash
frida -U -f owasp.mstg.uncrackable1 -l bypass_root_basic.js
```

### Résultat Visuel
![Injection Script Bypass](https://github.com/user-attachments/assets/c99889a3-071a-4999-b0b6-7bbfd4097276)

### Logs Obtenus
```
[+] Build.TAGS -> release-keys
[*] RootBeer non présent ou méthodes absentes
[+] File.exists hook installé
[+] Runtime.exec hooks installés
[+] Bypass Java installé
[+] File.exists bypass: /system/bin/su
[+] File.exists bypass: /system/xbin/su
[+] File.exists bypass: /system/app/Superuser.apk
```

### 🔍 Analyse Détaillée

| Fonction | Description |
|----------|-------------|
| **File.exists()** | Intercepte les vérifications de fichiers sensibles et retourne `false` |
| **Runtime.exec()** | Bloque l'exécution de commandes shell |
| **Build.TAGS** | Modifié pour simuler un build `release-keys` (non-root) |
| **RootBeer** | Détecte et contourne les vérifications de détection root |

### 🛡️ Chemins Contournés
- `/system/bin/su` - Binaire Superuser
- `/system/xbin/su` - Superuser alternatif
- `/system/app/Superuser.apk` - Application Superuser

---

## 🎮 Étape 3 – Exploration avec Objection

### Commande Exécutée
```bash
objection -g owasp.mstg.uncrackable1 explore --startup-command "android root disable"
```

### Résultat Visuel
![Objection Exploration](https://github.com/user-attachments/assets/a0f3a21c-2aa2-4ef5-9ad2-d4f221f73d00)

### Logs Obtenus
```
Checking for a newer version of objection...
DeprecationWarning: The option 'gadget' is deprecated. Please use '-n' or '--name' instead
DeprecationWarning: The command 'explore' is deprecated. Use 'objection start' instead of 'objection explore'
Running a startup command... android root disable
(agent) Registering job 945809. Name: root-detection-disable
Runtime Mobile Exploration
owasp.mstg.uncrackable1 (run) on (Android: 11) [usb] #
```

### ✨ Points Clés
- ✅ Objection s'attache automatiquement à l'application
- ✅ La commande `android root disable` est exécutée au démarrage
- ✅ La détection root est désactivée via un job Frida interne
- ✅ Accès à l'invite de commande interactive

---

## 📊 Récapitulatif des Hooks Actifs

| Hook | Cible | Effet |
|------|-------|-------|
| **Build.TAGS** | Construction système | Force `"release-keys"` |
| **File.exists()** | Fichiers SU/Superuser | Retourne `false` |
| **Runtime.exec()** | Commandes shell | Neutralise l'exécution |
| **Objection Job** | Détection root globale | Désactive tous les checks |

### Diagramme de Flux
```
Application (owasp.mstg.uncrackable1)
    ↓
Vérification Root Detection
    ↓
Hooks Frida/Objection
    ├─→ Build.TAGS → release-keys
    ├─→ File.exists → false
    ├─→ Runtime.exec → blocked
    └─→ RootBeer → disabled
    ↓
✅ Application Déverrouillée
```

---

## 💡 Conclusion du LAB 14

### 🎯 Objectif Atteint
L'application `owasp.mstg.uncrackable1` ne détecte plus l'environnement rooté de l'émulateur. Les hooks Frida et Objection permettent une exploration complète sans blocage.

### 📚 Acquis Techniques pour la Suite (LAB 15 – SSL Pinning)

| Compétence | Description |
|-----------|-------------|
| **Mode Spawn Frida** | Capacité à injecter des scripts au démarrage |
| **Classes Java à Hooker** | File, Runtime, Build |
| **Objection CLI** | Exploration dynamique de l'application |
| **Contournement Root** | Techniques de bypass des vérifications |

### 🚀 Prochaines Étapes
- Appliquer les techniques à d'autres applications
- Étudier le SSL Pinning (LAB 15)
- Exploiter les vulnérabilités de communication
- Analyser le stockage sécurisé des données

---

**Auteur:** bachirsoukaina  
**Date:** 2026-05-20  


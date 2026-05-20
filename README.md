# LAB14_SM - Contournement de la Détection Root avec Frida et Objection

## 📋 Table des Matières
- [Étape 1 - Vérification de Frida](#étape-1--vérification-de-frida)
- [Étape 2 - Injection du Script de Bypass](#étape-2--injection-du-script-de-bypass-root)
- [Étape 3 - Exploration avec Objection](#étape-3--exploration-avec-objection)
- [Analyse Comparative des Méthodes](#analyse-comparative-des-méthodes)
- [Récapitulatif des Hooks Actifs](#récapitulatif-des-hooks-actifs)
- [Enseignements Techniques](#enseignements-techniques)
- [Conclusion](#conclusion)

---

## ✅ Étape 1 – Vérification de Frida

### Commande Exécutée
```bash
frida -U -f owasp.mstg.uncrackable1 -l hello.js
```

### Résultat Visuel

<img width="838" height="317" alt="Étape 1 - Vérification Frida" src="https://github.com/user-attachments/assets/e14d8a2e-8388-4cfb-bc7e-4c8e279043b2" />

### Output Console
```
Connected to Android Emulator 5554 (id=emulator-5554)
Spawned `owasp.mstg.uncrackable1`. Resuming main thread!
[Android Emulator 5554::owasp.mstg.uncrackable1]-> [+] Script injecté : Java.perform OK
```

### 🎯 Observations & Interprétation

| ✅ Résultat | Détails |
|-----------|---------|
| **Frida-client ↔ Frida-server** | Communication établie avec l'émulateur Android 5554 |
| **Injection JavaScript** | Le script `hello.js` s'injecte correctement au démarrage |
| **Accès à la VM Java** | `Java.perform()` exécuté avec succès |
| **État de l'environnement** | Frida est opérationnel et prêt pour les hooks |

### 📌 Script hello.js Utilisé
```javascript
Java.perform(function() {
    console.log("[+] Script injecté : Java.perform OK");
});
```

---

## 🚫 Étape 2 – Injection du Script de Bypass Root

### Commande Exécutée
```bash
frida -U -f owasp.mstg.uncrackable1 -l bypass_root_basic.js
```

### Résultat Visuel

<img width="771" height="348" alt="Étape 2 - Injection Script Bypass" src="https://github.com/user-attachments/assets/1a197dac-630a-4b45-a489-0c7e0cd80ca5" />

### Output Console Détaillé
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

### 📝 Script bypass_root_basic.js - Implémentation

```javascript
Java.perform(function() {
    console.log("[+] Bypass Java installé");
    
    // ═══════════════════════════════════════════════════════════
    // 🔧 HOOK 1: Modification de Build.TAGS
    // ═══════════════════════════════════════════════════════════
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    console.log("[+] Build.TAGS -> " + Build.TAGS.value);
    
    // ═══════════════════════════════════════════════════════════
    // 🔧 HOOK 2: Interception de File.exists()
    // ═══════════════════════════════════════════════════════════
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getPath();
        
        // Chemins suspects typiques à bloquer
        var suspiciousPaths = [
            "su", "busybox", "Superuser.apk", "magisk", 
            "frida", "xposed", "prop"
        ];
        
        for (var i = 0; i < suspiciousPaths.length; i++) {
            if (path.indexOf(suspiciousPaths[i]) !== -1) {
                console.log("[+] File.exists bypass: " + path);
                return false;
            }
        }
        return this.exists();
    };
    console.log("[+] File.exists hook installé");
    
    // ═══════════════════════════════════════════════════════════
    // 🔧 HOOK 3: Interception de Runtime.exec()
    // ═══════════════════════════════════════════════════════════
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log("[+] exec bypass: " + cmd);
        
        if (cmd.indexOf("su") !== -1 || 
            cmd.indexOf("which") !== -1 || 
            cmd.indexOf("prop") !== -1) {
            throw new Error("Permission denied");
        }
        return this.exec(cmd);
    };
    console.log("[+] Runtime.exec hooks installés");
    
    // ═══════════════════════════════════════════════════════════
    // 🔧 HOOK 4: Contournement RootBeer (si présent)
    // ═══════════════════════════════════════════════════════════
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() bypassed");
            return false;
        };
    } catch(e) {
        console.log("[*] RootBeer non présent ou méthodes absentes");
    }
});
```

### 🔍 Analyse Détaillée des Hooks

| Fonction | Cible | Stratégie | Effet |
|----------|-------|-----------|-------|
| **Build.TAGS** | `android.os.Build.TAGS` | Substitution directe | Force `"release-keys"` au lieu de `"test-keys"` |
| **File.exists()** | `java.io.File.exists()` | Interception + filtrage | Retourne `false` pour `/system/bin/su`, `/system/xbin/su`, etc. |
| **Runtime.exec()** | `java.lang.Runtime.exec()` | Blocage conditionnel | Lance une exception si commande contient "su", "which", "prop" |
| **RootBeer** | `com.scottyab.rootbeer.RootBeer` | Override de méthode | Retourne toujours `false` (non-rooté) |

### 🛡️ Chemins Sensibles Contournés

```
/system/bin/su                  → Binaire Superuser standard
/system/xbin/su                 → Superuser alternatif
/system/app/Superuser.apk       → Application Superuser
/system/app/Magisk/              → Framework Magisk
/data/adb/magisk                → Données Magisk
/data/local/tmp/frida           → Frida injecté
```

### ✨ Points Clés de l'Étape 2

- ✅ **Tous les hooks sont actifs** - Build.TAGS, File.exists(), Runtime.exec()
- ✅ **Détection des chemins sensibles** - Les logs montrent les tentatives d'accès
- ✅ **Gestion des exceptions** - RootBeer est détecté comme absent (simplifie le bypass)
- ✅ **Pas de crash applicatif** - Les hooks retournent des valeurs cohérentes

---

## 🎮 Étape 3 – Exploration avec Objection

### Commande Exécutée
```bash
objection -g owasp.mstg.uncrackable1 explore --startup-command "android root disable"
```

### Résultat Visuel

<img width="792" height="281" alt="Étape 3 - Console Objection" src="https://github.com/user-attachments/assets/3ba8063f-9824-4e02-8d40-134d688e0770" />

### Output Console Détaillé
```
Checking for a newer version of objection...
DeprecationWarning: The option 'gadget' is deprecated. Please use '-n' or '--name' instead
DeprecationWarning: The command 'explore' is deprecated. Use 'objection start' instead of 'objection explore'
Running a startup command... android root disable
(agent) Registering job 945809. Name: root-detection-disable

Runtime Mobile Exploration
by: @leonjza from @sensepost

[tab] for command suggestions
owasp.mstg.uncrackable1 (run) on (Android: 11) [usb] #
```

### 🔍 Interprétation & Analyse

| 🎯 Événement | Détails |
|-------------|---------|
| **Connexion Objection** | Connexion établie via Frida au processus `owasp.mstg.uncrackable1` |
| **Job Frida Interne** | `job 945809` nommé `root-detection-disable` créé automatiquement |
| **Commande Startup** | `android root disable` exécutée à l'attachment de l'application |
| **État Console** | Invite interactive `#` prête pour des commandes supplémentaires |
| **OS Cible** | Android 11 sur l'émulateur USB |

### 🎮 Commandes Objection Utiles
```bash
# Navigation & reconnaissance
ls                                  # Lister les fichiers du sandbox
pwd                                 # Afficher le répertoire courant
env                                 # Variables d'environnement

# Inspection système
cat /system/build.prop              # Propriétés système
memory list modules                 # Modules chargés en mémoire
frida ps                            # Processus en cours

# Sécurité
android root disable                # Désactiver la détection root
android sslpinning disable          # Désactiver le SSL Pinning (LAB 15)

# Données
sqlite database list                # Énumérer les BD SQLite
file download <path>               # Télécharger un fichier
```

### ✨ Avantages de Objection vs Script Frida Brut

| Critère | Frida Pur | Objection |
|---------|-----------|----------|
| **Courbe d'apprentissage** | ⭐⭐ (JavaScript requis) | ⭐⭐⭐⭐ (CLI simples) |
| **Vitesse de déploiement** | ⭐⭐⭐ (40+ lignes code) | ⭐⭐⭐⭐⭐ (1 commande) |
| **Interactivité** | ❌ Requis redémarrage | ✅ REPL dynamique |
| **Flexibilité** | ⭐⭐⭐⭐⭐ (Totale) | ⭐⭐⭐ (Prédéfini) |
| **Contexte mobile** | ⭐⭐⭐ (Généraliste) | ⭐⭐⭐⭐⭐ (Mobile-focused) |

---

## 📊 Analyse Comparative des Méthodes

### Tableau de Comparaison

| Aspect | Frida Script | Objection CLI | Frida REPL |
|--------|--------------|--------------|-----------|
| **Configuration** | Script `.js` préconfiguré | `--startup-command` | Interactif |
| **Flexibilité** | Très haute | Moyenne | Très haute |
| **Courbe d'apprentissage** | Moyenne (JS) | Facile | Moyenne |
| **Reproductibilité** | ⭐⭐⭐⭐⭐ (Scriptable) | ⭐⭐⭐⭐ (Commande fixe) | ⭐⭐ (Manuelle) |
| **Debugging** | Logs détaillés | Logs automatiques | REPL directe |
| **Temps de déploiement** | 5-10 secondes | 3-5 secondes | 2 secondes |

### Diagramme Décisionnel

```
Objectif: Bypass root detection
    │
    ├─ Rapide & simple ? ─→ Objection (android root disable)
    │
    ├─ Highly customized ? ─→ Frida Script (.js)
    │
    └─ Debug/Explore ? ─→ Frida REPL (objection repl / frida console)
```

---

## 📊 Récapitulatif des Hooks Actifs

### Tableau Récapitulatif

| # | Hook | Classe Java | Méthode | Effet | Statut |
|----|------|----------|--------|-------|--------|
| 1️⃣ | **Build.TAGS** | `android.os.Build` | TAGS (property) | Force `"release-keys"` | ✅ Actif |
| 2️⃣ | **File.exists()** | `java.io.File` | exists() | Retourne `false` pour chemins suspects | ✅ Actif |
| 3️⃣ | **Runtime.exec()** | `java.lang.Runtime` | exec(String) | Bloque commandes dangereuses | ✅ Actif |
| 4️⃣ | **RootBeer.isRooted()** | `com.scottyab.rootbeer.RootBeer` | isRooted() | Retourne toujours `false` | ✅ Fallback |
| 5️⃣ | **Objection Job** | Frida (interne) | Job 945809 | Désactive globalement la détection root | ✅ Actif |

### Diagramme d'Architecture

```
┌─────────────────────────────────────────────────────────────┐
│        Application: owasp.mstg.uncrackable1                 │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   Code Applicatif (Root Detection Checks)          │   │
│  │   ├─ Vérif Build.TAGS == "test-keys" ?             │   │
│  │   ├─ Vérif File.exists("/system/bin/su") ?         │   │
│  │   ├─ Vérif Runtime.exec("which su") ?              │   │
│  │   └─ RootBeer.isRooted() ?                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   Hooks Frida (Intercepts les appels Java)         │   │
│  │   ├─ Build.TAGS.value = "release-keys"            │   │
│  │   ├─ File.exists() → return false                 │   │
│  │   ├─ Runtime.exec() → throw Exception              │   │
│  │   └─ RootBeer.isRooted() → return false           │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   Résultat: Toutes les vérifs retournent "OK"      │   │
│  │   ✅ Application pense qu'elle est en environnement│   │
│  │      non-rooté (Clean/Release)                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                          ↓                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │   🔓 Application Déverrouillée                      │   │
│  │   Accès complet aux fonctionnalités sensibles       │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Flux d'Exécution Détaillé

```
1. Démarrage de l'application
   ↓
2. Frida s'attache (spawn ou attach)
   ↓
3. Injection du script / Objection job
   ↓
4. Hooks installés sur les classes Java critiques
   ├─ Build.TAGS → "release-keys"
   ├─ File.exists → false (pour su/busybox)
   ├─ Runtime.exec → Exception (pour su)
   └─ RootBeer → false
   ↓
5. Application en route, effectue ses checks
   ├─ Appel à Build.TAGS → Reçoit "release-keys" ✅
   ├─ Appel à File.exists("/system/bin/su") → Reçoit false ✅
   ├─ Appel à Runtime.exec("which su") → Exception ✅
   └─ Appel à RootBeer.isRooted() → Reçoit false ✅
   ↓
6. Application conclut: "Pas de root détecté"
   ↓
7. 🔓 Déverrouillage complet
```

---

## 💡 Enseignements Techniques

### 🎯 Ce que j'ai Appris

#### 🔹 Frida - Instrumentation Dynamique

| Concept | Explication |
|---------|------------|
| **spawn vs attach** | `spawn`: lance l'app + injection | `attach`: se connecte à un processus |
| **Java.perform()** | Bloc de contexte pour opérations Java |
| **Hooking de méthodes** | `.implementation`: remplace la méthode entièrement |
| **Interception d'appels** | Voir les appels sans bloquer le flux |

#### 🔹 Détection Root - Mécanismes Courantes

```javascript
// Méthode 1: Propriétés système
var Build = Java.use('android.os.Build');
if (Build.TAGS.value.indexOf("test-keys") !== -1) {
    // Rooté détecté
}

// Méthode 2: Fichiers sensibles
var File = Java.use('java.io.File');
if (new File("/system/bin/su").exists()) {
    // Rooté détecté
}

// Méthode 3: Exécution de commandes
var Runtime = Java.use('java.lang.Runtime');
try {
    Runtime.getRuntime().exec("which su");
    // Rooté détecté
} catch(e) {
    // Pas de root
}

// Méthode 4: Librairies (RootBeer, RootShield)
if (com.scottyab.rootbeer.RootBeer.isRooted()) {
    // Rooté détecté
}
```

#### 🔹 Objection - Outils Mobile Orientés

| Commande | Cas d'usage |
|----------|------------|
| `android root disable` | Bypass détection root (LAB 14) |
| `android sslpinning disable` | Bypass SSL Pinning (LAB 15) |
| `memory list modules` | Découvrir les dépendances |
| `sqlite database list` | Énumérer les BD de l'app |
| `file download <path>` | Exfiltrer des données |

### 🚀 Techniques pour LAB 15 (SSL Pinning)

```javascript
// À l'étape suivante, je devrai hooker:

// 1. SSLContext
var SSLContext = Java.use('javax.net.ssl.SSLContext');
var getInstance = SSLContext.getInstance.overload('[Ljava/lang/String;')[0];
getInstance.implementation = function(protocol) {
    var ctx = getInstance.call(this, protocol);
    // Injector notre certificat custom
    return ctx;
};

// 2. HttpsURLConnection
var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
    // Accepter tous les certificats
    return;
};

// 3. OkHttp (très courant)
var OkHttp = Java.use('okhttp3.CertificatePinner');
OkHttp.check.overload('java.lang.String', '[Ljava/security/cert/Certificate;').implementation = function(hostname, certs) {
    console.log("[+] OkHttp SSL Pinning bypassed pour: " + hostname);
    return;
};
```

---

## ✅ Conclusion du LAB 14

### 🎯 Objectif Atteint ✨

L'application `owasp.mstg.uncrackable1` ne détecte plus qu'elle s'exécute dans un environnement rooté. Les hooks Frida et Objection permettent une **exploration complète sans blocage** des fonctionnalités sensibles.

### 📈 Résultats Mesurables

| Métrique | Avant Bypass | Après Bypass |
|----------|-------------|-------------|
| **Détection root** | ❌ Oui (bloquée) | ✅ Non (déverrouillée) |
| **Accès aux données** | ❌ Refusé | ✅ Autorisé |
| **Exécution de code** | ❌ Limitée | ✅ Complète |
| **Interactivité** | ❌ Restreinte | ✅ Totale |

### 📚 Acquis Techniques Réutilisables

| Compétence | Maîtrise | Application Future |
|-----------|----------|-------------------|
| **Mode Spawn Frida** | ⭐⭐⭐⭐⭐ | LAB 15, 16, 17+ |
| **Hooking Classes Java** | ⭐⭐⭐⭐ | Tous les labs mobiles |
| **File.exists / Runtime.exec** | ⭐⭐⭐⭐⭐ | Contournements génériques |
| **Objection CLI** | ⭐⭐⭐⭐ | Accélération des tests |
| **Analyse des Logs Frida** | ⭐⭐⭐⭐ | Debugging d'hooks |

### 🚀 Prochaines Étapes - LAB 15 et Au-Delà

```
LAB 14 (ROOT DETECTION) ✅ COMPLÉTÉ
    ↓
LAB 15 (SSL PINNING) → Hooker SSLContext, OkHttp, HttpsURLConnection
    ↓
LAB 16 (WEBVIEW) → Bridging JavaScript/Java, inspection DOM
    ↓
LAB 17 (CRYPTOGRAPHY) → Hooking de Cipher, SecureRandom
    ↓
...
```

### 💡 Conseils pour Maîtriser Frida

1. **Toujours utiliser `Java.perform()`** - Sinon les hooks ne fonctionnent pas
2. **Tester les logs en stdout** - `console.log()` est votre ami
3. **Gérer les exceptions** - `try/catch` pour les classes optionnelles
4. **Vérifier les overloads** - Beaucoup de méthodes Java ont plusieurs signatures
5. **Comprendre le flux d'exécution** - Un hook bien placé = moins de code

---

**Auteur:** `bachirsoukaina`  
**Date:** `2026-05-20`  
**Statut:** ✅ Complété  
**Prochaine Étape:** LAB 15 - SSL Pinning Bypass  

---

## 📖 Ressources Additionnelles

- [Documentation Frida](https://frida.re/docs/)
- [Objection GitHub](https://github.com/sensepost/objection)
- [OWASP MSTG - Root Detection](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
- [Android Security & Privacy](https://developer.android.com/privacy-and-security)

# Guide d'utilisation - Reverse Engineering B2

Ce dépôt contient une suite d'outils automatisés pour l'analyse et la résolution du binaire.

## Prérequis

* **Système** : Linux
* **Outils** : GDB (avec support Python), Python 3
* **Dépendances Python** :
```bash
pip install tqdm

```


---

## 1. Extraction du Payload (`extract_hidden.py`)

Ce script GDB lance le binaire original (`24.bin`), intercepte le déchiffrement en mémoire vive et extrait le payload caché avant son exécution.

* **Entrée** : `24.bin` (ou le nom de votre binaire original)
* **Sortie** : `hidden.bin` (ELF déchiffré)

**Commande :**

```bash
gdb -q -x extract_hidden.py ./24.bin

```

---

## 2. Extraction des Données Chiffrées (`extract_DAT.py`)

Ce script GDB agit de manière statique sur le payload extrait. Il copie la zone mémoire contenant le flag chiffré (tableau de référence) vers un fichier brut.

* **Entrée** (facultatif) : `hidden.bin` (Nom du fichier généré à l'étape 1)
* **Sortie** : `DAT.bin` (209 octets bruts)

**Commande :**

```bash
gdb -q -x extract_DAT.py [hidden.bin]

```

---

## 3. Résolution (Méthode Statique) (`solve_static.py`)

C'est la méthode la plus rapide et la plus élégante. Ce script Python casse l'algorithme de chiffrement en effectuant une attaque par force brute sur la graine (seed) de 15 bits et en inversant les opérations mathématiques (XOR/Rotation).

* **Entrée** (facultatif) : `DAT.bin` (Nom du fichier généré à l'étape 2)
* **Sortie** : Le Flag en clair.

**Commande :**

```bash
python3 solve_static.py [--file DAT.bin]

```

---

## 4. Résolution (Méthode Dynamique) (`solve_dynamic.py`)

Ce script GDB contourne les protections (Anti-Debug, Ptrace, Timing) en utilisant des **Breakpoints Hardware** invisibles. Il utilise une technique de "Time Travel" : si un caractère testé est incorrect, il rembobine le processeur (`$rip`) pour rejouer la boucle avec le caractère suivant.
 
* **Entrée** (facultatif) : `hidden.bin` (Nom du fichier généré à l'étape 1)
* **Sortie** : Le Flag en clair.

**Commande :**

```bash
gdb -q -x solve_dynamic.py [hidden.bin]

```

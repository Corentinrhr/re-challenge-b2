import sys
import logging
import argparse
from pathlib import Path
from tqdm import tqdm

# ================= CONFIGURATION DU LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stdout
)

# ================= CONSTANTES CRYPTOGRAPHIQUES =================
# Ces constantes sont extraites de l'analyse statique (Ghidra/IDA)
FLAG_SIGNATURE = "COURSE{"  # Signature connue du flag
SEED_SPACE     = 1 << 15    # Espace de recherche (15 bits = 32768 possibilités)
CONST_ADD_KEY  = 0xA5       # Constante additive identifiée dans la boucle de chiffrement

# ================= UTILITAIRES BIT À BIT =================

def ror8(val: int, rot: int) -> int:
    """
    Effectue une rotation binaire à droite sur 8 bits (Rotate Right).
    Opération inverse du ROL (Rotate Left) utilisé lors du chiffrement.
    
    Args:
        val (int): L'octet à tourner.
        rot (int): Le nombre de bits de rotation.
    """
    val &= 0xFF
    rot &= 7
    return ((val >> rot) | ((val << (8 - rot)) & 0xFF)) & 0xFF

# ================= LOGIQUE DE DÉCHIFFREMENT =================

def decrypt_candidate(encrypted_data: bytes, seed: int) -> bytearray:
    """
    Tente de déchiffrer le blob binaire avec une graine (seed) donnée.
    
    L'algorithme inverse les opérations identifiées :
    1. Cipher = ROL(Plain ^ Key1, i%5) ^ Key2
    2. Plain  = ROR(Cipher ^ Key2, i%5) ^ Key1
    
    Args:
        encrypted_data (bytes): Le contenu du fichier dumpé.
        seed (int): La graine candidate (0-32767).
        
    Returns:
        bytearray: Le buffer déchiffré potentiel.
    """
    out = bytearray()
    
    for i, byte_val in enumerate(encrypted_data):
        # 1. Dérivation de la Clé 1 (basée sur la seed et la position)
        # Formule : (seed >> (i & 7)) & 0xff
        key1 = (seed >> (i & 7)) & 0xFF

        # 2. Dérivation de la Clé 2 (Additive, constante de boucle)
        # Formule : (i + 0xA5) & 0xff
        key2 = (i + CONST_ADD_KEY) & 0xFF

        # 3. Opérations inverses
        tmp = byte_val ^ key2    # Annulation du XOR additif
        tmp = ror8(tmp, i % 5)   # Annulation de la rotation (ROR inverse de ROL)
        plain = tmp ^ key1       # Annulation du XOR initial
        
        out.append(plain & 0xFF)
        
    return out

def is_valid_flag(buffer: bytearray) -> bool:
    """Vérifie si le buffer déchiffré contient la signature du flag."""
    try:
        # Tentative de décodage ASCII pour vérifier la lisibilité
        decoded = buffer.decode("ascii")
        if FLAG_SIGNATURE in decoded:
            return True
    except UnicodeDecodeError:
        pass # Contient des bytes non-ASCII, probablement pas le bon flag
    return False

# ================= MAIN EXECUTION =================

def run_static_solver(filepath: str):
    path = Path(filepath)
    
    if not path.exists():
        logging.error(f"Le fichier '{filepath}' est introuvable.")
        logging.info("Conseil : Dumper la mémoire si ce fichier n'existe pas.")
        sys.exit(1)

    logging.info(f"Chargement du fichier chiffré : {filepath}")
    try:
        encrypted_data = path.read_bytes()
        logging.info(f"Taille du blob : {len(encrypted_data)} octets")
    except Exception as e:
        logging.error(f"Erreur de lecture : {e}")
        sys.exit(1)

    logging.info(f"Démarrage de l'attaque par force brute sur l'espace de clé (2^{15})...")
    
    found_flag = None
    found_seed = None

    # Barre de progression
    with tqdm(total=SEED_SPACE, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} seeds", dynamic_ncols=True) as pbar:
        for seed in range(SEED_SPACE):
            candidate = decrypt_candidate(encrypted_data, seed)
            
            if is_valid_flag(candidate):
                found_flag = candidate.decode("ascii")
                found_seed = seed
                pbar.update(SEED_SPACE - seed) # Finir la barre proprement
                break
            
            pbar.update(1)

    # Résultat
    if found_flag:
        print("\n") # Séparation visuelle
        logging.info("Candidat valide identifié.")
        logging.info(f"Seed Cryptographique : {found_seed} (0x{found_seed:04x})")
        logging.warning(f"FLAG DÉCHIFFRÉ : {found_flag}")
    else:
        logging.error("Échec du brute-force. Aucun flag correspondant à la signature n'a été trouvé.")
        logging.info(f"Vérifiez la constante CONST_ADD_KEY ({hex(CONST_ADD_KEY)}) ou l'algo de rotation.")

if __name__ == "__main__":
    # Configuration du parser d'arguments
    parser = argparse.ArgumentParser(description="Static Flag Solver (Brute-force low15 seed)")
    parser.add_argument("--file", default="DAT.bin", help="Chemin vers le fichier binaire dumpé (ex: DAT.bin)")
    
    args = parser.parse_args()
    
    run_static_solver(args.file)
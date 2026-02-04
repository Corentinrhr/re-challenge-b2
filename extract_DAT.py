import gdb
import logging
import sys
import os

# ================= CONFIGURATION DU LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stdout
)

# ================= CONFIGURATION CIBLE =================
OUTPUT_FILENAME = "DAT.bin"      # Le fichier de sortie
TARGET_ADDR     = 0x4a60e0       # Adresse du tableau chiffré (Hardcodée dans le binaire)
TARGET_SIZE     = 209            # Taille (0xd1) correspondant à la boucle for

# ================= CLASSE D'EXTRACTION =================

class DatExtractor:
    def __init__(self):
        self.output_path = os.path.abspath(OUTPUT_FILENAME)

    def load_target(self):
        """Charge le binaire dans GDB sans l'exécuter."""
        target_filename = "hidden.bin" # Défaut
        
        try:
            current_loaded = gdb.current_progspace().filename
        except:
            current_loaded = None

        if current_loaded:
            target_filename = current_loaded
            logging.info(f"Cible détectée (arguments GDB) : {target_filename}")
        else:
            logging.info(f"Aucune cible chargée. Utilisation du défaut : {target_filename}")
            try:
                gdb.execute(f"file {target_filename}")
            except gdb.error as e:
                logging.error(f"Impossible de charger {target_filename}: {e}")
                logging.info("Conseil : Dumper le fichier hidden.bin si ce fichier n'existe pas.")
                return False
        return True

    def verify_mapping(self):
        """Vérifie si l'adresse cible est accessible (mappée)."""
        try:
            # On tente de lire 1 octet à l'adresse cible
            inferior = gdb.selected_inferior()
            # Note: Si le programme n'est pas lancé, read_memory lit le fichier sur le disque
            # grâce à la commande 'file', ce qui est exactement ce qu'on veut.
            inferior.read_memory(TARGET_ADDR, 1)
            return True
        except gdb.MemoryError:
            logging.error(f"L'adresse {hex(TARGET_ADDR)} n'est pas accessible.")
            logging.info("Le binaire est peut-être PIE (Position Independent) ou corrompu.")
            return False

    def dump(self):
        """Effectue l'extraction vers le fichier."""
        start = TARGET_ADDR
        end   = TARGET_ADDR + TARGET_SIZE
        
        logging.info(f"Tentative d'extraction : {hex(start)} -> {hex(end)} ({TARGET_SIZE} octets)")
        
        try:
            # Commande GDB native pour dumper la mémoire brute
            cmd = f"dump binary memory {OUTPUT_FILENAME} {start} {end}"
            gdb.execute(cmd)
            
            if os.path.exists(self.output_path):
                file_size = os.path.getsize(self.output_path)
                if file_size == TARGET_SIZE:
                    logging.info(f"SUCCÈS ! Fichier généré : {self.output_path}")
                    logging.info(f"Taille vérifiée : {file_size} octets.")
                else:
                    logging.warning(f"Fichier généré mais taille incorrecte ({file_size} octets).")
            else:
                logging.error("La commande dump a semblé fonctionner mais aucun fichier n'a été créé.")
                
        except gdb.error as e:
            logging.error(f"Échec du dump : {e}")

# ================= MAIN EXECUTION =================

def run_extractor():    
    logging.info("--- Extracteur de Données Statiques (DAT.bin) ---")
    
    extractor = DatExtractor()
    
    # Configuration GDB
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

    # 1. Chargement
    if not extractor.load_target():
        gdb.execute("quit")
        return

    # 2. Vérification (Optionnelle mais recommandée)
    if not extractor.verify_mapping():
        logging.error("Impossible d'accéder à la section .data/rodata.")
        gdb.execute("quit")
        return

    # 3. Extraction
    extractor.dump()
    
    # Fin
    gdb.execute("quit")

if __name__ == "__main__":
    run_extractor()
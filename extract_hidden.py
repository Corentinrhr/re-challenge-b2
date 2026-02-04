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
OUTPUT_FILENAME = "hidden.bin"
MAGIC_ELF = b'\x7fELF'

# ================= ÉTAT DU PROCESSUS =================
class ExtractionState:
    dumped = False
    payload_addr = 0
    payload_size = 0

state = ExtractionState()

# ================= LOGIQUE DE BREAKPOINTS =================

class WriteInterceptor(gdb.Breakpoint):
    """
    Breakpoint placé sur la fonction 'write' de la libc.
    Responsabilité : Inspecter les buffers écrits pour détecter un en-tête ELF.
    
    ABI Linux x86_64 pour write(fd, buf, count) :
    - $rdi : File Descriptor
    - $rsi : Adresse du buffer (Ce qui nous intéresse)
    - $rdx : Taille (Ce qui nous intéresse)
    """
    def stop(self):
        try:
            # Récupération des arguments selon la convention d'appel System V AMD64
            buf_addr = int(gdb.parse_and_eval("$rsi"))
            count = int(gdb.parse_and_eval("$rdx"))
            
            # Lecture des 4 premiers octets pour vérifier la signature ELF
            inferior = gdb.selected_inferior()
            try:
                # Lecture mémoire sécurisée via l'API GDB
                header = inferior.read_memory(buf_addr, 4).tobytes()
            except gdb.MemoryError:
                return False # Buffer invalide ou non mappé, on ignore

            # Vérification de la signature
            if header == MAGIC_ELF:
                logging.info(f"Signature ELF détectée à l'adresse {hex(buf_addr)} (Taille: {count} octets)")
                
                # Mise à jour de l'état
                state.payload_addr = buf_addr
                state.payload_size = count
                state.dumped = True
                
                # --- ACTION DE DUMP ---
                logging.info(f"Extraction en cours vers '{OUTPUT_FILENAME}'...")
                
                # Utilisation de la commande dump de GDB
                # Syntaxe : dump memory <fichier> <debut> <fin>
                cmd = f"dump memory {OUTPUT_FILENAME} {buf_addr} {buf_addr + count}"
                gdb.execute(cmd)
                
                logging.info(f"Extraction réussie ! Fichier généré : {os.path.abspath(OUTPUT_FILENAME)}")
                return True # Arrêt de l'exécution (On a fini)
                
        except Exception as e:
            logging.error(f"Erreur dans l'intercepteur : {e}")
            
        return False # Ce n'était pas un ELF, on continue l'exécution

# ================= MAIN EXECUTION =================

def run_extractor():
    logging.info("--- Démarrage de l'extracteur automatique ---")
    
    # Détection automatique du binaire chargé
    try:
        current_loaded = gdb.current_progspace().filename
        if not current_loaded:
            raise ValueError("Aucun")
        logging.info(f"Cible : {current_loaded}")
    except:
        logging.error("Erreur : Aucun binaire chargé dans GDB.")
        logging.info("Usage: gdb -x extract_hidden.py <votre_loader>")
        return

    # Configuration GDB pour la performance et le silence
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    
    # Installation du Hook sur 'write'
    try:
        # On tente de breaker sur le symbole write
        WriteInterceptor("write")
        logging.info("Intercepteur installé sur la fonction 'write'.")
    except Exception as e:
        logging.warning(f"Impossible de hooker 'write' ({e}). Tentative sur '__write'...")
        try:
            WriteInterceptor("__write")
        except:
            logging.error("Échec de l'installation des hooks. Le binaire est-il strippé statique ?")
            return

    logging.info("Lancement du processus...")
    
    # On lance le programme. 
    # Pas besoin de fichier d'input particulier pour le loader, il déchiffre tout seul.
    try:
        gdb.execute("run")
    except gdb.error:
        # GDB lève une erreur quand le programme s'arrête (via notre return True ou un exit)
        pass

    if state.dumped:
        logging.info("--- Opération terminée avec SUCCÈS ---")
        gdb.execute("quit")
    else:
        logging.error("Le programme s'est terminé sans qu'aucun ELF ne soit détecté dans un appel write().")
        gdb.execute("quit")

if __name__ == "__main__":
    run_extractor()
import gdb
import logging
import sys
import argparse
from tqdm import tqdm

# ================= CONFIGURATION DU LOGGING =================
# Format : [Heure] [Niveau] Message
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stdout
)

# ================= ADRESSES MÉMOIRES (Binaire) =================
# Ces adresses correspondent aux points critiques du graphe de contrôle.
ADDR_LOOP_START  = 0x402cc3  # Début de la boucle de traitement d'un caractère
ADDR_CHECK_JUMP  = 0x402d4d  # Instruction conditionnelle vérifiant la validité du caractère
ADDR_GET_BUFFER  = 0x402c55  # Instruction suivant l'allocation du buffer utilisateur
ADDR_ANTI_PTRACE = 0x402bcd  # Appel ptrace() pour anti-debug
ADDR_ANTI_TIME   = 0x402c21  # Vérification temporelle (RDTSC/Time)


# ================= ÉTAT DU PROCESSUS =================
class ProcessState:
    buffer_addr = None
    saved_context = {"rsp": 0, "rbp": 0}
    current_char_val = 32  # ASCII Space (début de la plage imprimable)
    found_flag = ""
    pbar = None            # Instance tqdm

# Instanciation de l'état global
state = ProcessState()

# Références globales aux breakpoints pour la gestion de la machine à états
bp_context_saver = None
bp_brute_forcer = None

# Flag
FLAG_SIZE = 209

# ================= LOGIQUE DE BREAKPOINTS =================

class ContextSaverBreakpoint(gdb.Breakpoint):
    """
    Breakpoint positionné au début de la boucle de calcul (ADDR_LOOP_START).
    Responsabilité : Capturer l'état sain des registres (Snapshot) avant modification.
    """
    def stop(self):
        # 1. Sauvegarde des registres de pile critiques
        # Cela permet de restaurer la stack frame en cas d'échec ultérieur.
        state.saved_context["rsp"] = int(gdb.parse_and_eval("$rsp"))
        state.saved_context["rbp"] = int(gdb.parse_and_eval("$rbp"))
        
        # 2. Transition d'état
        # Le contexte est sauvé. On désactive ce breakpoint pour laisser l'exécution
        # se poursuivre jusqu'à la vérification (CHECK_JUMP).
        self.enabled = False
        bp_brute_forcer.enabled = True
        
        return False # Continuer l'exécution

class BruteForceBreakpoint(gdb.Breakpoint):
    """
    Breakpoint positionné sur le saut conditionnel (ADDR_CHECK_JUMP).
    Responsabilité : Vérifier l'accumulateur d'erreur et manipuler le pointeur d'instruction (RIP).
    """
    def stop(self):
        try:
            # Lecture de la variable locale de contrôle [rbp-0x14]
            # Si cette valeur est 0, le caractère testé est valide.
            check_val = int(gdb.parse_and_eval("*(int*)($rbp-0x14)"))
            current_index = int(gdb.parse_and_eval("*(int*)($rbp-0x18)"))
        except Exception as e:
            logging.error(f"Erreur de lecture mémoire : {e}")
            return True # Arrêt de sécurité

        if check_val == 0:
            # --- SUCCÈS ---
            # Le caractère courant est valide.
            char = chr(state.current_char_val)
            state.found_flag += char
            
            # Mise à jour de l'interface
            if state.pbar:
                state.pbar.update(1)
                
                # On coupe pour ne montrer que les 20 derniers
                display_str = state.found_flag[-20:]
                prefix = "..." if len(state.found_flag) > 20 else ""
                
                state.pbar.set_description(f"Decoded: {prefix}{display_str}")

            # Réinitialisation pour le prochain caractère
            state.current_char_val = 32
            
            # Transition d'état : On réactive le Saver pour la prochaine itération de boucle
            self.enabled = False
            bp_context_saver.enabled = True
            
            return False # Continuer vers le caractère suivant
        
        else:
            # --- ÉCHEC ---
            # Le caractère est invalide. Incrémentation et nouvel essai.
            state.current_char_val += 1
            
            if state.current_char_val > 126: # Limite ASCII imprimable (~)
                if state.pbar: state.pbar.close()
                logging.error(f"Espace de recherche épuisé à l'index {current_index}. Arrêt.")
                return True

            # 1. Injection du nouveau candidat en mémoire
            if state.buffer_addr:
                offset = state.buffer_addr + current_index
                gdb.execute(f"set *(unsigned char*)({offset}) = {state.current_char_val}")
            
            # 2. Restauration du contexte (Stack Frame)
            # Restaure la pile telle qu'elle était au début de la boucle.
            gdb.execute(f"set $rsp = {state.saved_context['rsp']}")
            gdb.execute(f"set $rbp = {state.saved_context['rbp']}")
            
            # 3. Nettoyage de l'accumulateur d'erreur (CRITIQUE)
            # Force la variable locale à 0 pour éviter la persistance de l'erreur précédente.
            gdb.execute("set *(int*)($rbp-0x14) = 0")
            
            # 4. Modification du pointeur d'instruction (Time Travel)
            # Retour au début de la boucle pour re-tester avec la nouvelle valeur.
            # Note : bp_context_saver est désactivé, donc pas d'arrêt inutile.
            gdb.execute(f"set $rip = {ADDR_LOOP_START}")
            
            return False # Continuer l'exécution (rejouer la boucle)

class InitializationBreakpoint(gdb.Breakpoint):
    """
    Breakpoint unique pour initialiser l'environnement une fois le buffer alloué.
    """
    def stop(self):
        try:
            # Calcul de l'adresse du buffer utilisateur basé sur RBP
            rbp_val = int(gdb.parse_and_eval("$rbp"))
            state.buffer_addr = rbp_val - 0x110
            logging.info(f"Adresse du buffer identifiée : {hex(state.buffer_addr)}")
        except Exception:
            logging.warning("Impossible de résoudre l'adresse du buffer.")
        
        # Suppression des breakpoints d'initialisation (nettoyage)
        gdb.execute("del") 
        
        logging.info("Initialisation de la machine à états (ContextSaver <-> BruteForcer).")
        
        # Initialisation de la barre de progression (Estimation sur 209 chars d'input)
        state.pbar = tqdm(total=209, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}", dynamic_ncols=True)
        
        # Création des breakpoints persistants
        global bp_context_saver, bp_brute_forcer
        bp_context_saver = ContextSaverBreakpoint(f"*{ADDR_LOOP_START}", type=gdb.BP_HARDWARE_BREAKPOINT)
        bp_brute_forcer = BruteForceBreakpoint(f"*{ADDR_CHECK_JUMP}", type=gdb.BP_HARDWARE_BREAKPOINT)
        
        # État initial : Saver Actif, BruteForcer Inactif
        bp_brute_forcer.enabled = False
        
        return False

class AntiDebugBypass(gdb.Breakpoint):
    """Contournement des protections (Ptrace/Time) en forçant le registre de retour RAX à 0."""
    def stop(self):
        gdb.execute("set $rax = 0")
        return False

# ================= MAIN EXECUTION =================

def run_solver():
    logging.info("Préparation de l'environnement GDB...")
    
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
            return
    
    # Génération du fichier d'entrée (Placeholder)
    with open("input.txt", "w") as f:
        f.write(" " * FLAG_SIZE) # Remplissage avec des espaces
    
    # Configuration GDB
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    # ASLR Désactivé pour garantir la stabilité des adresses si non-PIE ou debug statique
    gdb.execute("set disable-randomization on") 
    

    # Configuration de l'entrée standard du processus
    logging.info("Configuration de l'entrée standard (stdin) via input.txt")
    gdb.execute("set args < input.txt")

    logging.info("Démarrage du processus en mode 'starti'...")
    gdb.execute("starti")

    # Installation des hooks de phase 1
    logging.info("Installation des Hooks de contournement et d'initialisation.")
    AntiDebugBypass(f"*{ADDR_ANTI_PTRACE}", type=gdb.BP_HARDWARE_BREAKPOINT)
    AntiDebugBypass(f"*{ADDR_ANTI_TIME}", type=gdb.BP_HARDWARE_BREAKPOINT)
    InitializationBreakpoint(f"*{ADDR_GET_BUFFER}", type=gdb.BP_HARDWARE_BREAKPOINT)

    logging.info("Lancement de l'exécution continue. Le bruteforce démarrera automatiquement.")
    gdb.execute("continue")
    logging.warning(f"FLAG COMPLET TROUVÉ : {state.found_flag}")
    gdb.execute("q")
    
if __name__ == "__main__":
    run_solver()
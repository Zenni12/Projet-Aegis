# j'importe les modules dont j'ai besoin

# subprocess ca permet de lancer des commandes linux depuis python

# json ca sert a sauvegarder les resultats proprement

# datetime ca donne la date et l'heure

import subprocess

import json

import datetime

 

# je cree un dictionnaire vide pour stocker tous les resultats

# comme ca tout est au meme endroit et c'est plus facile a exporter apres

results = {}

 

# on note la date et l'heure de l'audit

# comme ca on sait quand le scan a ete fait

results['date'] = str(datetime.datetime.now())

 

print("=" * 55)

print("  AUDIT DE SECURITE - BTC1")

print(f"  Date : {results['date']}")

print("=" * 55)

 

 

 

# 1. Inventaire des ports en ecoute

# ============================================================

# On liste tous les services actifs sur la machine

# la commande 'ss -tuln' affiche les ports qui ecoutent

# -t = tcp, -u = udp, -l = en ecoute, -n = pas resoudre les noms

 

print("\n[1/5] Scan des ports en ecoute...")

 

try:

    # subprocess.getoutput ca lance la commande et recupere le resultat en texte

   

    out = subprocess.getoutput('ss -tuln')

    results['ports'] = out

    print(out)

 

except Exception as e:

    # si ca marche pas on met quand meme quelque chose dans results

    print(f"  Erreur : {e}")

    results['ports'] = f"Erreur : {e}"

 

 

# ============================================================

# 2. Verification des ports ouverts (attendus vs inattendus)

# ============================================================

# On verifie quels ports sont exposes et si c'est normal

# par exemple le port 22 (SSH) c'est normal, le port 4444 c'est suspect

 

print("\n[2/5] Verification des ports attendus vs inattendus...")

 

# liste des ports qui sont normaux sur un serveur linux de base

# j'ai fait cette liste avec ce qu'on a vu en cours

PORTS_ATTENDUS = [22, 80, 443, 53, 25, 587, 3306, 5432]

 

ports_suspects = []

 

# on parcourt les lignes du resultat ss -tuln pour extraire les ports

for ligne in results['ports'].split('\n'):

    # on cherche les lignes qui ont une adresse IP et un port

    # le format c'est : tcp  LISTEN  0  128  0.0.0.0:22  0.0.0.0:*

    if 'LISTEN' in ligne or 'UNCONN' in ligne:

        try:

            # l'adresse locale c'est la 5eme colonne (index 4)

            parties = ligne.split()

            adresse_locale = parties[4]

 

            # le port c'est ce qui est apres le dernier ":"

            # exemple : "0.0.0.0:22" -> port 22

            # exemple : "[::]:80"    -> port 80

            port_str = adresse_locale.split(':')[-1]

            port = int(port_str)

 

            if port not in PORTS_ATTENDUS:

                ports_suspects.append(port)

                print(f"  [!] Port inattendu detecte : {port}")

 

        except (ValueError, IndexError):

            # si on arrive pas a parser la ligne on passe

            pass

 

if len(ports_suspects) == 0:

    print("  OK : Aucun port inattendu trouve")

else:

    print(f"  ATTENTION : {len(ports_suspects)} port(s) inattendu(s) !")

 

results['ports_suspects'] = ports_suspects

 

 

# ============================================================

# 3. Controle de la configuration SSH

# ============================================================

# On verifie les parametres importants de SSH :

# - PermitRootLogin : est-ce que root peut se connecter directement ?

# - PasswordAuthentication : est-ce qu'on peut se connecter avec un mot de passe ?

# - Port : est-ce que SSH tourne sur le port par defaut (22) ?

 

print("\n[3/5] Verification de la configuration SSH...")

 

# on utilise grep pour chercher les lignes qui nous interessent

# dans le fichier de config de SSH

ssh_root = subprocess.getoutput(

    'grep PermitRootLogin /etc/ssh/sshd_config'

)

ssh_password = subprocess.getoutput(

    'grep PasswordAuthentication /etc/ssh/sshd_config'

)

ssh_port = subprocess.getoutput(

    'grep "^Port" /etc/ssh/sshd_config'

)

 

# on stocke les resultats

results['ssh_root']     = ssh_root

results['ssh_password'] = ssh_password

results['ssh_port']     = ssh_port

 

# on affiche et on analyse les resultats

print(f"  PermitRootLogin        : {ssh_root.strip() or 'non configure (defaut = yes, DANGER)'}")

print(f"  PasswordAuthentication : {ssh_password.strip() or 'non configure (defaut = yes)'}")

print(f"  Port SSH               : {ssh_port.strip() or 'non configure (defaut = 22)'}")

 

if 'no' in ssh_root.lower():

    print("  OK : root ne peut pas se connecter directement en SSH")

else:

    print("  PROBLEME : PermitRootLogin n'est pas desactive !")

 

if 'no' in ssh_password.lower():

    print("  OK : authentification par mot de passe desactivee")

else:

    print("  PROBLEME : les mots de passe SSH sont autorises (risque brute force)")

 

 

# ============================================================

# 4. Verification de fail2ban

# ============================================================

# fail2ban c'est un service qui protege contre les attaques brute force

# il lit les logs et bloque automatiquement les IPs suspectes

# On verifie :

#   - que le service est actif

#   - que la jail SSH est bien configuree

 

print("\n[4/5] Verification de fail2ban...")

 

# on demande a systemctl si fail2ban tourne

# systemctl is-active repond "active" si ca tourne, "inactive" sinon

f2b = subprocess.getoutput(

    'systemctl is-active fail2ban'

)

results['fail2ban'] = f2b

 

print(f"  Statut fail2ban : {f2b}")

 

if f2b.strip() == 'active':

    print("  OK : fail2ban est actif")

 

    # si fail2ban tourne on verifie aussi les jails (les regles de blocage)

    jails = subprocess.getoutput('fail2ban-client status')

    results['fail2ban_jails'] = jails

    print(f"\n  Jails configurees :\n  {jails}")

 

    # on verifie specifiquement que la jail SSH est la

    jail_ssh = subprocess.getoutput('fail2ban-client status sshd')

    results['fail2ban_jail_ssh'] = jail_ssh

 

    if 'Currently banned' in jail_ssh:

        print(f"\n  Jail SSH active :\n  {jail_ssh}")

    else:

        print("  ATTENTION : La jail SSH ne semble pas active !")

 

else:

    print("  PROBLEME : fail2ban n'est pas actif !")

    print("  Pour l'installer : sudo apt install fail2ban")

    print("  Pour l'activer   : sudo systemctl enable --now fail2ban")

    results['fail2ban_jails']    = "fail2ban non actif"

    results['fail2ban_jail_ssh'] = "fail2ban non actif"

 

 

# ============================================================

# 5. Export JSON et CSV

# ============================================================

# On sauvegarde tous les resultats dans des fichiers

# JSON c'est pratique pour les programmes, CSV pour Excel

 

print("\n[5/5] Export des resultats...")

 

# --- Export JSON ---

# indent=2 ca met une indentation pour que ce soit lisible

try:

    with open('audit_report.json', 'w') as f:

        json.dump(results, f, indent=2)

    print("  Fichier JSON cree : audit_report.json")

 

except Exception as e:

    print(f"  Erreur JSON : {e}")

 

# --- Export CSV ---

# j'utilise pas le module csv pour rester simple

try:

    with open('audit_report.csv', 'w') as f:

        f.write("cle,valeur\n")

        for cle, valeur in results.items():

            # on remplace les virgules et retours a la ligne

            # sinon ca casse le format CSV

            valeur_propre = str(valeur).replace(',', ';').replace('\n', ' | ')

            f.write(f"{cle},{valeur_propre}\n")

    print("  Fichier CSV cree  : audit_report.csv")

 

except Exception as e:

    print(f"  Erreur CSV : {e}")

 

 

 

# FIN

 

print("\n" + "=" * 55)

print("  Audit termine - audit_report.json")

print("=" * 55)

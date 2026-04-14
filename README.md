# 🛡️ Projet AEGIS — Audit & Sécurisation SI TechSud

![Classification](https://img.shields.io/badge/classification-confidentiel_pédagogique-red)
![École](https://img.shields.io/badge/école-IPSSI-blue)
![Promo](https://img.shields.io/badge/promo-BTC1-lightgrey)

Audit et sécurisation d'un système d'information compromis — Mission de réponse à incident pour l'entreprise fictive **TechSud SAS** (distribution industrielle B2B, 47 collaborateurs, Toulouse).

---

## 📌 Contexte

Le vendredi 18 avril 2026, le serveur principal de TechSud a été victime d'une intrusion détectée via une saturation CPU anormale (98 %). Une connexion SSH active depuis un nœud de sortie Tor, un webshell PHP déposé via un formulaire non sécurisé et un processus masqué communiquant vers un serveur C2 ont été identifiés.

Ce projet vise à auditer l'infrastructure, identifier les vecteurs d'attaque et sécuriser les systèmes.

---

## 🎯 Objectifs de la semaine

| Jour | Objectif |
|------|----------|
| Lundi | Analyse du dossier, cartographie des vecteurs d'attaque, répartition des rôles |
| Mardi | Déploiement VM Debian 12, SSH sécurisé (clé, port custom, no-root) |
| Mercredi | Pare-feu `ufw`, `fail2ban`, gestion des permissions et utilisateurs |
| Jeudi | Script Python d'audit, analyse des logs, rédaction du rapport |
| Vendredi | Rapport final, rendu GitHub, soutenance avec démo |

---

## 🔍 Périmètre technique

Infrastructure composée de 6 équipements sur le réseau `192.168.1.0/24` :
serveurs Debian/Ubuntu, pare-feu pfSense, NAS Synology.

Services exposés identifiés : SSH, HTTP (sans HTTPS), SMB, MariaDB.

Éléments suspects : webshell PHP (`shell.php`), backdoor ELF (`sshd_bak`), cron malveillant, compte `deploy` réactivé à distance.



from encoding import Encoding
from hashing import Hashing
from sym_encryption import SymEncryption
from asym_encryption import AsymEncryption

import stdiomask

while True:
    print("* Projet sécurité:")
    print("1. Codage et décodage d'un message.")
    print("2. Hachage d'un message.")
    print("3. Craquage d'un message haché.")
    print("4. Chiffrement et déchiffrement symétrique d'un message.")
    print("5. Chiffrement et déchiffrement asymétrique d'un message.")
    print("6. Quitter")
    print()

    choix = input("Choix: ")
    print()

    if choix == "6": break

    if choix == "1":
        while True:
            print("1. Saisie et codage d'un message.")
            print("2. Décodage d'un message codé.")
            print("3. Retour.")
            print()

            choix = input("Choix: ")
            print()
            
            if choix == "3": break

            if choix == "1":
                message = input("Message: ")
                methode = ""
                while (not (methode in ["utf8", "ascii", "base64", "base32", "base16"])):
                    methode = input(
                        "Méthode de codage (utf8, ascii, base64, base32, base16): ").lower()
                
                encoded = Encoding.encode(methode, message)
                print("Le message codé est: ")
                print(encoded)
                print()
            
            if choix == "2":
                message = input("Message codé: ")
                methode = ""
                while (not (methode in ["utf8", "ascii", "base64", "base32", "base16"])):
                    methode = input(
                        "Méthode de codage (utf8, ascii, base64, base32, base16): ").lower()

                decoded = Encoding.decode(methode, message)
                print("Le message décodé est: ")
                print(decoded)
                print()

    elif choix == "2":
        message = input("Message: ")
        algo = ""
        while (not (algo in ["md5", "sha1", "sha256", "sha512"])):
            algo = input(
                "Fonction de hachage (md5, sha1, sha256, sha512): ").lower()

        hach = Hashing.hash(algo, message)
        print("Le hache est: ")
        print(hach)
        print()

    elif choix == "3":
        hach = input("Hache: ")
        algo = ""
        while (not (algo in ["md5", "sha1", "sha256", "sha512"])):
            algo = input("Fonction de hachage (md5, sha1, sha256, sha512): ").lower()

        message = Hashing.crack(algo, hach)
        print("Le message est: ")
        print(message)
        print()

    elif choix == "4":
        while True:
            print("1. Saisie du message à chiffrer.")
            print("2. Saisie du message chiffré.")
            print("3. Retour.")
            print()

            choix = input("Choix: ")
            print()

            if choix == "3": break

            if choix == "1":
                message = input("Message: ")
                mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")

                algo = ""
                while (not (algo in ["aes128", "aes256", "des"])):
                    algo = input("Fonction de hachage (aes128, aes256, des): ").lower()

                encrypted = SymEncryption.encrypt(algo, mdp, message)
                print("Le message chiffré est: ")
                print(encrypted)
                print()
            if choix == "2":
                encrypted = input("Message chiffré: ")
                mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")

                (algo, message) = SymEncryption.decrypt(mdp, encrypted)
                if algo == None:
                    print("Le message chiffré est ")
                    print()
                else:
                    print(f"Le message est chiffré avec {algo}.")
                    print("Le message déchiffré: ")
                    print(message)
                    print()


    elif choix == "5":
        while True:
            print("1. Génération d'une paire de clefs.")
            print("2. Chiffrement d'un message.")
            print("3. Déchiffrement d'un message.")
            print("4. Signature d'un message avec RSA.")
            print("5. Vérification de la signature d'un message avec RSA.")
            print("6. Retour")
            print()

            choix = input("Choix: ")
            print()

            if choix == "6": break

            if choix == "1":
                algo = ""
                while (not (algo in ["rsa", "elgamal"])):
                    algo = input("Algorithme de chiffrement (rsa, elgamal): ").lower()
                
                nom = ""
                while True:
                    nom = input("Nom de la paire de clefs: ")
                    if (algo == "rsa" and AsymEncryption.RSA_keypair_exists(nom)) or (algo == "elgamal" and AsymEncryption.ElGamal_keypair_exists(nom)):
                        choix = input(f"La clef identifiée par '{nom}' existe déja. Ecraser? (oui, non): ")
                        
                        if choix == "oui": break
                    else:
                        break
                
                if algo == "rsa":
                    mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")
                    paire = AsymEncryption.gen_RSA_keypair(mdp, nom)
                    print(f"La paire de clefs RSA a été crée avec succès sous le nom '{nom}'.")
                    print()
                else:
                    paire = AsymEncryption.gen_ElGamal_keypair(nom)
                    print(f"La paire de clefs ElGamal a été crée avec succès sous le nom '{nom}'.")
                    print()

            elif choix == "2":
                message = input("Message: ")
                algo = ""
                while (not (algo in ["rsa", "elgamal"])):
                    algo = input("Algorithme de chiffrement (rsa, elgamal): ").lower()

                nom = input("Nom de la paire de clefs: ")

                if (algo == "rsa" and not AsymEncryption.RSA_keypair_exists(nom)) or (algo == "elgamal" and not AsymEncryption.ElGamal_keypair_exists(nom)):
                    print(f"La paire de clefs identifiée par '{nom}' n'existe pas.")
                    print()
                    continue

                encrypted = ""
                if (algo == "rsa"):
                    mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")
                    paire = AsymEncryption.RSA_get_keypair(mdp, nom)
                    encrypted = AsymEncryption.RSA_encrypt(message, paire)
                else:
                    paire = AsymEncryption.ElGamal_get_keypair(nom)
                    encrypted = AsymEncryption.ElGamal_encrypt(message, paire)

                print("Le message chiffré est: ")
                print(encrypted)
                print()

            elif choix == "3":
                encrypted = input("Message chiffré: ")
                algo = ""
                while (not (algo in ["rsa", "elgamal"])):
                    algo = input("Algorithme de chiffrement (rsa, elgamal): ").lower()

                nom = input("Nom de la paire de clefs: ")

                if (algo == "rsa" and not AsymEncryption.RSA_keypair_exists(nom)) or (algo == "elgamal" and not AsymEncryption.ElGamal_keypair_exists(nom)):
                    print(f"La paire de clefs identifiée par '{nom}' n'existe pas.")
                    print()
                    continue

                decrypted = ""
                if (algo == "rsa"):
                    mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")
                    paire = AsymEncryption.RSA_get_keypair(mdp, nom)
                    decrypted = AsymEncryption.RSA_decrypt(encrypted, paire)
                else:
                    paire = AsymEncryption.ElGamal_get_keypair(nom)
                    decrypted = AsymEncryption.ElGamal_decrypt(encrypted, paire)

                print("Le message déchiffré est: ")
                print(decrypted)
                print()
            elif choix == "4":
                message = input("Message: ")
                nom = input("Nom de la paire de clefs: ")

                if not AsymEncryption.RSA_keypair_exists(nom):
                    print(f"La paire de clefs identifiée par '{nom}' n'existe pas.")
                    print()
                    continue

                mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")
                paire = AsymEncryption.RSA_get_keypair(mdp, nom)
                signed = AsymEncryption.RSA_sign(message, paire)

                print("La signature est: ")
                print(signed)
                print()
            elif choix == "5":
                signed = input("Message signé: ")
                sig = input("Signature: ")
                nom = input("Nom de la paire de clefs: ")

                if not AsymEncryption.RSA_keypair_exists(nom):
                    print(f"La paire de clefs identifiée par '{nom}' n'existe pas.")
                    print()
                    continue

                mdp = stdiomask.getpass(prompt="Mot de passe: ", mask="*")
                paire = AsymEncryption.RSA_get_keypair(mdp, nom)
                verif = AsymEncryption.RSA_verify(signed, sig, paire)

                if verif:
                    print("Le message est valide.")
                    print()
                else:
                    print("Le message n'est pas valide.")
                    print()

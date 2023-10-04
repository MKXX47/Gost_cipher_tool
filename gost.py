"""
Ce fichier reprend les fonctions permettant un chiffrement
et un déchiffrement GOST suivant différents modes d'opération
"""
import threading

from gost_feistel_function import gost_feistel_function
from key_generator import *
from utilities import *
from utilities import _64bits_block_to_bytearray


def feistel(block, key, swap=True):
    """
    Cette fonction applique l'ensemble des transformations effectuées à chaque round.

    :param block: Le block de 64 bits à transformer
    :param key: La clé de 32 bits locale au round
    :param swap: Booléen permettant de spécifier si un swap final entre les parties L et R est requis.
    :return: Le bloc de 64 bits transformé.
    """
    right_part = block & 2 ** 32 - 1  # on prend la partie droit du block
    left_part = block >> 32  # on prend la partie gauche du block

    right = gost_feistel_function(key,
                                  right_part)  # on applique la fonction (gost_feistel_function) sur la partie droit
    left_xor = left_part ^ right

    if swap:
        return (right_part << 32) | left_xor
    else:
        return (left_xor << 32) | right_part


def encrypt_block(block, key_array):
    """
    Cette fonction permet de chiffrer un bloc de 64 bits suivant la méthode GOST.
    :param block: bloc de 64 bits à chiffrer
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :return: Le bloc de 64 bits chiffré.
    """
    block_encrypted = feistel(block, key_array[0], swap=True)
    for i in range(1, 31):
        block_encrypted = feistel(block_encrypted, key_array[i], swap=True)
    block_encrypted = feistel(block_encrypted, key_array[31], swap=False)
    return block_encrypted


def encryptECB(blocks, key_array):
    """
    Cette fonction applique le chiffrement GOST à une liste de blocs de 64 bits suivant le mode d'opération ECB.
    :param blocks: Liste de blocs à chiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :return: la liste de blocs chiffrés.
    """
    encrypted_blocks = list()

    for block in blocks:  # on encrypt block par block
        encrypted_blocks.append(encrypt_block(block, key_array))

    return encrypted_blocks


def encryptCBC(blocks, key_array):
    """
    Cette fonction applique le chiffrement GOST à une liste de blocs de 64 bits suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à chiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    encrypted_blocks = list()
    iv = rdm_IV_generator()  # On génère un vecteur initial
    encrypted_blocks.append(iv)
    # On parcourt la liste de blocs à chiffrer en se basant sur sa taille
    for i in range(len(blocks)):
        operation_xor = encrypted_blocks[i] ^ blocks[i]
        encrypted_block = encrypt_block(operation_xor, key_array)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks


def CTR_thread(iv, ct, block, key_array, encrypted_blocks):
    ct_xor_iv = iv ^ ct  # on xor le vecteur d'initialisation et le compteur
    encrypted_counter = encrypt_block(ct_xor_iv, key_array)
    operation_xor = block ^ encrypted_counter
    encrypted_blocks.append(operation_xor)


def encryptCTR(blocks, key_array):
    """
    Cette fonction applique le chiffrement GOST à une liste de blocs de 64 bits
    suivant le mode d'opération CTR.
    :param blocks: Liste de blocs à chiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :return: la liste de blocs chiffrés.
    """
    encrypted_blocks = list()
    iv = rdm_IV_generator()  # on génére le vecteur d'initialisation
    encrypted_blocks.append(iv)
    ct = 0  # le compteur
    for block in blocks:  # pour chaque block on crée un thread
        thread = threading.Thread(target=CTR_thread, args=(iv, ct, block, key_array, encrypted_blocks,))
        thread.start()
        ct += 1

    return encrypted_blocks


def encrypt(blocks, key_array, operation_mode="ECB"):
    """
    Cette fonction applique le chiffrement GOST à une liste de blocs de 64 bits.
    :param blocks: Liste de blocs à chiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :param operation_mode: string spécifiant le mode d'opération ("ECB", "CBC" ou "CTR")
    :return: la liste de blocs chiffrés avec le vecteur initial utilisé en première position.
    """
    if operation_mode == "ECB":
        return encryptECB(blocks, key_array)
    elif operation_mode == "CBC":
        return encryptCBC(blocks, key_array)
    elif operation_mode == "CTR":
        return encryptCTR(blocks, key_array)


def decrypt_block(block, key_array):
    """
    Cette fonction permet de déchiffrer un bloc de 64 bits qui a été chiffré préalablement
     suivant la méthode GOST.
    :param block: bloc de 64 bits à chiffrer
    :param key_array: liste ordonnée des 32 clés locales pour chaque round
    :return: Le bloc de 64 bits déchiffré.
    """
    block_decrypted = feistel(block, key_array[31], swap=True)
    for i in range(30, 0, -1):  # on inverse l'ordre des rounds
        block_decrypted = feistel(block_decrypted, key_array[i], swap=True)
    block_decrypted = feistel(block_decrypted, key_array[0], swap=False)

    return block_decrypted


def decryptECB(blocks, key_array):
    """
    Cette fonction dé-chiffre une liste de blocs de 64 bits qui a été préalablement chiffrée
    avec la méthode GOST suivant le mode d'opération ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round.
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_blocks = list()

    for block in blocks:
        decrypted_blocks.append(decrypt_block(block, key_array))

    return decrypted_blocks


def decryptCBC(blocks, key_array):
    """
    Cette fonction dé-chiffre une liste de blocs de 64 bits qui a été préalablement chiffrée
    avec la méthode GOST suivant le mode d'opération CBC.
    :param blocks: Liste de blocs à déchiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round.
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_blocks = list()
    blocks_mod = blocks[1:]  # liste des blocks sans le vecteur d'initialisation
    for i in range(len(blocks_mod)):
        decrypted_block = decrypt_block(blocks_mod[i], key_array)
        operation_xor = decrypted_block ^ blocks[i]
        decrypted_blocks.append(operation_xor)

    return decrypted_blocks


def decryptCTR(blocks, key_array):
    """
    Cette fonction dé-chiffre une liste de blocs de 64 bits qui a été préalablement chiffrée
    avec la méthode GOST suivant le mode d'opération CTR.
    :param blocks: Liste de blocs à déchiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round.
    Identique à celle utilisée pour le chiffrement.
    :return: la liste de blocs déchiffrés.
    """
    decrypted_blocks = list()
    iv = blocks[0]
    blocks_mod = blocks[1:]  # liste des blocks sans le vecteur d'initialisation
    ct = 0
    for i in range(len(blocks_mod)):
        ct_xor_iv = iv ^ ct  # on xor le vecteur d'initialisation et le compteur
        decrypted_counter = encrypt_block(ct_xor_iv, key_array)
        operation_xor = blocks_mod[i] ^ decrypted_counter
        decrypted_blocks.append(operation_xor)
        ct += 1
    return decrypted_blocks


def decrypt(blocks, key_array, operation_mode="ECB"):
    """
    Cette fonction dé-chiffre une liste de blocs de 64 bits qui a été préalablement chiffrée
    avec la méthode GOST suivant le mode d'opération CBC ou ECB.
    :param blocks: Liste de blocs à déchiffrer.
    :param key_array: liste ordonnée des 32 clés locales pour chaque round.
    Identique à celle utilisée pour le chiffrement.
    :param operation_mode: string spécifiant le mode d'opération ("ECB", "CBC" ou "CTR")
    :return: la liste de blocs déchiffrés.
    """
    if operation_mode == "ECB":
        return decryptECB(blocks, key_array)
    elif operation_mode == "CBC":
        return decryptCBC(blocks, key_array)
    elif operation_mode == "CTR":
        return decryptCTR(blocks, key_array)


def encrypt_file(input_filename, output_filename, operation_mode="ECB", simple_key=True):
    """
    Cette fonction chiffre un fichier avec la méthode GOST suivant le mode d'opération CBC ou ECB.
    Les fonctions de lecture du fichier fournies dans utilities.py peuvent être utiles
    :param input_filename: Nom du fichier à chiffrer
    :param output_filename: Nom du fichier chiffré
    :param operation_mode: string spécifiant le mode d'opération ("ECB", "CBC" ou "CTR")
    :param simple_key: utilise la clé de base du GOST si True, sinon utilise le schéma avancé(voir énoncé)
    :return: La clé utilisée pour le chiffrement.
    """
    key_256 = rdm_key_generator()  # on génère une clé aléatoire
    mask = 2 ** 128 - 1
    key_128 = key_256 & mask  # on recupére les premier 128bits de la clé du 256bits
    if simple_key:
        key_array = gost_key_generator(key_256)  # clé simple
    else:
        key_array = gost_advanced_key_generator(key_128)  # clé avancé

    txt = load_txt_file(input_filename)  # on lit le fichier
    blocks = bytearray_to_64bits_block(txt.encode())  # on convertit le fichier en liste de blocs de 64 bits

    encrypted_blocks = encrypt(blocks, key_array, operation_mode)  # on chiffre le fichier
    encrypted_bin = _64bits_block_to_bytearray(encrypted_blocks)  # on convertit la liste de blocs en bytes

    save_to_bin(output_filename, encrypted_bin)  # on écrit le fichier chiffré

    return key_array  # on retourne la clé utilisée pour le chiffrement


def decrypt_file(input_filename, output_filename, key, operation_mode="ECB"):
    """
    Cette fonction dé-chiffre un fichier qui a été préalablement chiffré
    avec la méthode GOST suivant le mode d'opération CBC ou ECB.
    Les fonctions de lecture du fichier fournies dans utilities.py peuvent être utiles

    :param input_filename: le nom du fichier chiffré.
    :param output_filename: le nom du fichier déchiffré
    :param key: La clé de 64 bits utilisée pour chiffrer le fichier.
    :param operation_mode: string spécifiant le mode d'opération ("ECB", "CBC" ou "CTR")
    """
    binary = load_from_bin(input_filename)  # on charge le fichier
    blocks = bytearray_to_64bits_block(binary)  # on convertit le fichier en liste de blocs de 64 bits

    decrypted_blocks = decrypt(blocks, key, operation_mode)  # on déchiffre le fichier
    decrypted_bin = _64bits_block_to_bytearray(decrypted_blocks)  # on convertit la liste de blocs en bytes

    save_txt_file(output_filename, decrypted_bin.decode())  # on écrit le fichier déchiffré

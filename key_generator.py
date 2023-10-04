"""
Ce fichier comprend toutes les foncitons liées à la génération de clés.
"""

from random import *

from permutation import *

"""
Liste d'indices de permutation permettant de dropper les bits de parité de la clé globale.
"""
PARITY_DROP_TABLE = [57, 49, 41, 33, 25, 17, 9, 1,
                     58, 50, 42, 34, 26, 18, 10, 2,
                     59, 51, 43, 35, 27, 19, 11, 3,
                     60, 52, 44, 36, 63, 55, 47, 39,
                     31, 23, 15, 7, 62, 54, 46, 38,
                     30, 22, 14, 6, 61, 53, 45, 37,
                     29, 21, 13, 5, 28, 20, 12, 4]

"""
Liste d'indices de permutation permettant de combiner les deux parties de 28 bits
pour créer la clé locale à chaque round (compression D-box dans 
https://academic.csuohio.edu/yuc/security/Chapter_06_Data_Encription_Standard.pdf
et dans l'énoncé du projet).
"""
D_BOX_TABLE = [14, 17, 11, 24, 1, 5, 3, 28,
               15, 6, 21, 10, 23, 19, 12, 4,
               26, 8, 16, 7, 27, 20, 13, 2,
               41, 52, 31, 37, 47, 55, 30, 40,
               51, 45, 33, 48, 44, 49, 39, 56,
               34, 53, 46, 42, 50, 36, 29, 32]


def rdm_key_generator():
    """
    Cette fonction doit pouvoir générer une clé aléatoire de 256bits
    :return: un entier représenté sur 256 bits généré de manière aléatoire.
    """
    return getrandbits(256)


def rdm_IV_generator():
    """
    Cette fonction doit pouvoir générer un nombre aléatoire de 64bits
    :return: un entier représenté sur 64 bits généré de manière aléatoire.
    """
    return getrandbits(64)


def gost_key_generator(key):
    """
    Cette fonction renvoie une liste des 32 clés nécessaires pour chacun des rounds du GOST avancé.
    Les clés doivent être ordonnées (premier élément = clé pour round 1, etc.). On considère que les 8
    bits les plus faibles sont utilisés pour le round 1.
    :param key: Clé globale de 256 bits
    :return: Liste ordonnée de 32 clés locales utilisées pour chacun des rounds.
    """
    key_list = list()
    mask = 2 ** 32 - 1
    i = 0
    while i < 8:
        key_r = key & mask
        key_list.append(key_r)
        key = key >> 32
        i += 1
    final_list = key_list * 3
    key_list.reverse()
    final_list += key_list

    return final_list


def gost_advanced_key_generator(key):
    """
    Cette fonction renvoie une liste des 32 clés nécessaires pour chacun des rounds du GOST avancé.
    Les clés doivent être ordonnées (premier élément = clé pour round 1, etc.)
    :param key: Clé globale de 128 bits
    :return: Liste ordonnée de 32 clés locales utilisées pour chacun des rounds.
    """
    rounds_key_list = list()
    mask = 2 ** 64 - 1

    # on découpe la clé en 2 parties de 64 bits
    key_left = (key >> 64 & mask)
    key_right = (key & mask)
    # on appelle la fonction (gost_advanced_subkey_generator) pour chaque partie de la clé global
    key_list_r = gost_advanced_subkey_generator(key_right)
    key_list_l = gost_advanced_subkey_generator(key_left)
    # on ordonne les clé
    for i in range(len(key_list_r)):
        rounds_key_list.append(key_list_r[i])
        rounds_key_list.append(key_list_l[i])

    return rounds_key_list


def gost_advanced_subkey_generator(key_lr):
    """
    Cette fonction renvoie une liste des 16 clés nécessaires pour chacun des rounds du GOST avancé
    à partir d'une sous-clé de 64 bits gauche ou droite (voir énoncé).
    Les clés doivent être ordonnées (premier élément = clé pour round 1, etc.)
    :param key_lr: Clé de 64 bits issue d'une clé globale de 128 bits
    :return: Liste ordonnée de 16 clés locales.
    """
    key_list = list()
    mask = 2 ** 32 - 1

    key = permutation(key_lr, PARITY_DROP_TABLE, 64)  # on enleve les 8 bits de parité (56 bits)

    k28_l = key >> 28
    k28_r = key & 2 ** 28 - 1

    for i in range(1, 17):  # on génère les 16 clés locales
        if i in (1, 2, 9, 16):  # on fait un shift gauche de 1 bit pour chaque round 1, 2, 9 et 16
            k28_l = shift_left(k28_l, 28, 1)
            k28_r = shift_left(k28_r, 28, 1)

        else:  # on applique un shift de 2 bits pour le reste
            k28_l = shift_left(k28_l, 28, 2)
            k28_r = shift_left(k28_r, 28, 2)

        new_k56 = (k28_l << 28) | k28_r  # On reconstruit la clé après shift
        new_k48 = permutation(new_k56, D_BOX_TABLE, 56)  # On applique la permutation D-box
        final_key = new_k48 & mask  # on recupére les premier 32bits
        key_list.append(final_key)  # On ajoute la clé locale à la liste des clés de rounds

    return key_list

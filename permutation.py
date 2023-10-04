"""
Ce fichier comprend toutes les foncitons liées aux permutations.

Bon ok, il n'y en a qu'une.
"""


def permutation(block, new_position, input_size):
    """
    CETTE FONCTION N'EST UTILISEE QUE POUR LA VERSION AVANCEE DE GENERATION DE CLE, A FAIRE A LA FIN!!!
    Cette fonction permet de permuter un bloc de bits suivant une liste contenant les nouveaux indices et en précisant
    la taille du block.
    Par exemple, si le block donné est '0b101' et les nouvelles positions voulues est [2 3 1] (input_size=3)
    alors la fonction retournera '0b011'.

    !!! Attention !!! Les indices commence à 1 pour le premier élément.
    :param block: Block de bits à permuter (sous forme d'entier).
    :param new_position: Liste de nouveaux indices (1 = premier élément)
    :param input_size: Nombre de bits du block initial.
    :return: un block de bits permuté (sous forme d'entier).
    """
    permuted_block = 0
    permutation_size = len(new_position)  # la taille de la permutation

    for i in range(permutation_size, 0, -1):
        bit = (block >> (input_size - new_position[
            permutation_size - i])) & 1  # récupération du bit à la position new_position[i]
        permuted_block |= bit << i - 1  # ajout du bit au block final via un (OU)
    return permuted_block  # on obtient le block permuté



def shift_left(data, input_size, n_bit):
    """
    Cette fonction doit être capable de barrel-shifter vers la gauche de n_bit éléments
    l'argument data de taille input_size
    :param data: L'entier à shifter.
    :param input_size: La taille en bits de data.
    :param n_bit: nombre de bit à shifter
    :return: L'entier data shifté de 1 vers la gauche
    """
    mask1 = 2 ** input_size - 1
    mask2 = 2 ** n_bit - 1
    shift_l = (data >> input_size - n_bit) & mask2
    shift_r = (data << n_bit) & mask1
    final_result = shift_r | shift_l
    return final_result

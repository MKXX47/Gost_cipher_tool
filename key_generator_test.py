import unittest

from key_generator import *


class Test_key_generator(unittest.TestCase):


    def test_gost_key_generator(self):
        keys = gost_key_generator(0x0000000800000007000000060000000500000004000000030000000200000001)
        assert keys[0] == int(1)
        assert keys[1] == int(2)
        assert keys[2] == int(3)
        assert keys[3] == int(4)
        assert keys[4] == int(5)
        assert keys[5] == int(6)
        assert keys[6] == int(7)
        assert keys[7] == int(8)
        assert keys[8] == int(1)
        assert keys[9] == int(2)
        assert keys[10] == int(3)
        assert keys[11] == int(4)
        assert keys[12] == int(5)
        assert keys[13] == int(6)
        assert keys[14] == int(7)
        assert keys[15] == int(8)
        assert keys[16] == int(1)
        assert keys[17] == int(2)
        assert keys[18] == int(3)
        assert keys[19] == int(4)
        assert keys[20] == int(5)
        assert keys[21] == int(6)
        assert keys[22] == int(7)
        assert keys[23] == int(8)
        assert keys[24] == int(8)
        assert keys[25] == int(7)
        assert keys[26] == int(6)
        assert keys[27] == int(5)
        assert keys[28] == int(4)
        assert keys[29] == int(3)
        assert keys[30] == int(2)
        assert keys[31] == int(1)

    def test_gost_advanced_key_generator(self):
        keys = gost_advanced_key_generator(0xAABB09182736CCDDAABB09182736CCDD)
        assert keys[0] == int(0xD072DE8C)
        assert keys[2] == int(0x581ABCCE)
        assert keys[4] == int(0xA4ACF5B5)
        assert keys[6] == int(0x032B6EE3)
        assert keys[8] == int(0x29FEC913)
        assert keys[10] == int(0x8E87475E)
        assert keys[12] == int(0xD2DDB3C0)
        assert keys[14] == int(0x22F0C66D)
        assert keys[16] == int(0x4473DCCC)
        assert keys[18] == int(0x5708B5BF)
        assert keys[20] == int(0x60AF7CA5)
        assert keys[22] == int(0xE96A4BF3)
        assert keys[24] == int(0x1397C91F)
        assert keys[26] == int(0x8BC717D0)
        assert keys[28] == int(0xC5D9A36D)
        assert keys[30] == int(0x5D75C66D)
        assert keys[1] == int(0xD072DE8C)
        assert keys[3] == int(0x581ABCCE)
        assert keys[5] == int(0xA4ACF5B5)
        assert keys[7] == int(0x032B6EE3)
        assert keys[9] == int(0x29FEC913)
        assert keys[11] == int(0x8E87475E)
        assert keys[13] == int(0xD2DDB3C0)
        assert keys[15] == int(0x22F0C66D)
        assert keys[17] == int(0x4473DCCC)
        assert keys[19] == int(0x5708B5BF)
        assert keys[21] == int(0x60AF7CA5)
        assert keys[23] == int(0xE96A4BF3)
        assert keys[25] == int(0x1397C91F)
        assert keys[27] == int(0x8BC717D0)
        assert keys[29] == int(0xC5D9A36D)
        assert keys[31] == int(0x5D75C66D)
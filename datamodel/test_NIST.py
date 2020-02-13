from typing import TypeVar, Generic, Type
from unittest import TestCase

from datamodel.Dictionary_Parser import DictionaryParser
from datamodel.CWE_NIST import CWE_NIST


class TestNIST(TestCase):
    def test_parse(self):
        self.fail()

    def test_winning(self):
        nist = CWE_NIST()
        nist.test()
        print()


    def isclass(self, clazz: Type[DictionaryParser]):
        clazz.parse()



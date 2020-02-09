from unittest import TestCase

from datamodel.CWE import CWE
from datamodel.Taxonomy import Mapping


class TestCWE(TestCase):




    def test_get_last_owasp_empty(self):
        cwe = CWE("23", "test", "test test", mappings=[])
        cwe.get_latest_owasp()

    def test_get_latest_owasp(self):
        mappings = []
        latest = Mapping(source='OWASP Top Ten 2037', id="A7")
        mappings.append(Mapping(source='OWASP Top Ten 2017', id="A7"))
        mappings.append(Mapping(source='OWASP Top Ten 2027', id="A7"))
        mappings.append(latest)
        mappings.append(Mapping(source='OWASP Top Ten 2007', id="A7"))
        cwe = CWE("22", "test", "test test", mappings)
        result = cwe.get_latest_owasp()
        self.assertEqual(latest, result)


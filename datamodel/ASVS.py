from typing import Dict, List

from datamodel.Dictionary_Parser import DictionaryParser
from datamodel.NIST import NIST
from datamodel.NISTPublication import NISTPublication


class ASVS(DictionaryParser):

    def __init__(self, section: str, name: str, item: str, description: str, l1: str, l2: str, l3: str, cwe: str,
                 nist_publications: List[NISTPublication]):
        self.section = section
        self.name = name
        self.item = item
        self.description = description
        self.l1 = l1
        self.l3 = l3
        self.l2 = l2
        self.cwe = cwe
        self.nist_publications: List[NISTPublication] = nist_publications

    def merge_data(self, data):
        pass

    def add_nist_info(self, nist_info: NISTPublication):
        self.nist_publications.append(nist_info)

    @classmethod
    def parse(cls, item: Dict):
        results: List[NISTPublication] = []
        nist = item["NIST"]
        if "/" in nist:
            for section in nist.split("/"):
                section = str(section).strip()
                results.append(NISTPublication(publication="800_63", version=None, nist_data=NIST(id=section)))
        """This is coming form the ASVS dictionary. Which means that this could have """
        return ASVS(section=item["Section"], name=item["Name"], item=item["Item"], description=item["Description"],
                    l1=item["L1"], l2=item["L2"], l3=item["L3"], cwe=item["CWE"], nist_publications=results)

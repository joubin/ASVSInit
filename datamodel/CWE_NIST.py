from datamodel.Dictionary_Parser import DictionaryParser


class CWE_NIST(DictionaryParser):
    def __init__(self, id, name, cwe_id, cwe_name):
        self.cwe_name:str = cwe_name
        self.cwe_id:str = cwe_id
        self.name:str = name
        self.id: str = id


    @classmethod
    def parse(cls, item):
        return CWE_NIST(id=item["NIST-ID"], name=item["NIST Name"], cwe_id=item["CWE-ID"], cwe_name=item["CWE Name"])

    def merge_data(self, data):
        raise NotImplementedError



from datamodel.Dictionary_Parser import DictionaryParser


class CWE(DictionaryParser):
    def __init__(self, id: str, name: str = None, description: str = None):
        self.id = id
        self.name = name
        self.description = description

    @classmethod
    def parse(cls, item):
        pass


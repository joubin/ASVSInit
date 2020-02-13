from __future__ import annotations

from datamodel.Dictionary_Parser import DictionaryParser


class NIST(DictionaryParser):
    def __init__(self, id: str, name: str = None, description: str = None):
        self.id: str = id
        self.name = name
        self.description = description

    @classmethod
    def parse(cls, item):
        pass

    def merge_data(self, data: NIST):
        if self.name is None:
            self.name = data.name
        if self.description is None:
            self.description = data.description

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, type(self)):
            return False
        return self.id == o.id



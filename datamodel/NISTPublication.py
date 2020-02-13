from __future__ import annotations

import logging
from typing import Optional, List

from datamodel.Dictionary_Parser import DictionaryParser
from datamodel.NIST import NIST
from datamodel.NISTCollection import NISTCollection


class NISTPublication(DictionaryParser):
    def __init__(self, publication: str, version: Optional[str], nist_data: NIST):
        self.publication: str = publication
        self.version: str = version
        self.nist: NISTCollection = [nist_data]

    def get_data_by_id(self, nist_id):
        return self.nist.get_by_nist_id(nist_id=nist_id)

    def add_data(self, data: NIST):
        # See if we already have something with this data
        data_subset = self.get_data_by_id(data.id)
        if len(data_subset) == 1:
            # If we already have it, just take it and merge data because we could be missing fields
            data_subset.pop().merge_data(data)
        elif len(data_subset) == 0:
            # if we dont have anything, just add it
            self.nist.append(data)
        else:
            # we have more than 1 item and thats bad, these should be unique
            logging.error("in the class {self}, found more than one nist item by key in the list.\n {items}\n"
                          "Incoming data: {data}".format(self=self, items=data_subset, data=data))

    def merge_data(self, data: NISTPublication):
        if self.publication is None or self.publication == "":
            self.publication = data.publication
        if self.version is None or self.version == "":
            self.version = data.version




    @classmethod
    def parse(cls, item):
        pass

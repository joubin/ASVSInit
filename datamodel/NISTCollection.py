from __future__ import annotations

from typing import List

from datamodel.NIST import NIST


class NISTCollection:
    def __init__(self):
        self.__collection: List[NIST] = []

    def get_by_nist_id(self, nist_id):
        return list(filter(lambda nist: (nist_id == nist.id), self.__collection))

    def add(self, data: NIST):
        # See if we already have something with this data
        data_subset = self.get_by_nist_id(data.id)
        if len(data_subset) == 1:
            # If we already have it, just take it and merge data because we could be missing fields
            data_subset.pop().merge_data(data)
        elif len(data_subset) == 0:
            # if we dont have anything, just add it
            self.__collection.append(data)
        else:
            import logging
            # we have more than 1 item and thats bad, these should be unique
            logging.error("in the class {self}, found more than one nist item by key in the list.\n {items}\n"
                          "Incoming data: {data}".format(self=self, items=data_subset, data=data))

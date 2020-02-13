from typing import Dict

from datamodel.CWE_NIST import CWE_NIST
from datamodel.NIST import NIST
from datamodel.NISTPublication import NISTPublication


class NISTPublicationCollection:
    def __init__(self):
        self.__collection : Dict[str, NISTPublication] = {}

    def add_publication_to_collection(self, publication: NISTPublication):
        self.__collection[publication.publication] = publication

    def get(self, key):
        return self.__collection.get(key)

    def add_cwenist_to_collection(self, nist_data: CWE_NIST):
        nist = NIST(id=nist_data.id, name=nist_data.name)
        publication = NISTPublication(publication="800_53", version="4", nist_data=nist)
        self.add_publication_to_collection(publication=publication)

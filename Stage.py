import collections
import logging
import os
import shutil
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, TypeVar, Generic
from zipfile import ZipFile

from datamodel.ASVS import ASVS
from datamodel.ASVSInit import ASVSInit
from datamodel.CWE_NIST import CWE_NIST
from datamodel.CWE_OWASP import CWE_OWASP
from datamodel.Dictionary_Parser import DictionaryParser
from datamodel.Taxonomy import Mapping

T = TypeVar("T")


class Default(dict):
    def __missing__(self, key):
        return ''


class Stage(object):
    """
    Class to Stage and parse the required content from CWE.
    """

    def __init__(self):
        self.downloads = Stage.get_downloads_location()
        self.cwe_xml_location = self.downloads.joinpath("1026.xml")
        if not self.downloads.exists():
            os.mkdir(self.downloads)
            self.download_zip_file(url="https://github.com/OWASP/ASVS/archive/v4.0.1.zip")
            self.download_zip_file(url="https://cwe.mitre.org/data/xml/views/1026.xml.zip")
            self.download_zip_file(url="https://github.com/mitre/heimdall_tools/archive/v1.3.2.zip")
        self.init_dir = Stage.get_init_location()
        if not self.init_dir.exists(): os.mkdir(self.init_dir)
        self.image_path = self.init_dir.joinpath("images")
        if not self.image_path.exists(): os.mkdir(self.image_path)
        self.asvs_init: List[ASVSInit] = []

    @staticmethod
    def get_init_location():
        """

        :return: Returns the @{Path} for the init folder
        """
        return Path(os.getcwd()).joinpath("init")

    @staticmethod
    def get_downloads_location():
        """

        :return: Returns the @{Path} for the downloads folder
        """
        return Path(os.getcwd()).joinpath("downloads")

    def download_file(self, url, path: Path = None):
        if path is None:
            logging.info("Downloading {url}".format(url=url))
            temp = self.downloads.joinpath("temp")
        else:
            temp = path
        urllib.request.urlretrieve(url, filename=temp)
        return temp

    def download_zip_file(self, url: str, path: Path = None):
        """

        :param url: Given this url, it will download it to where `get_downloads_location` specifies.
        :return:
        """
        temp = self.download_file(url=url, path=path)
        with ZipFile(temp, "r") as my_zip_file:
            my_zip_file.extractall(self.downloads)
        if os.path.exists(temp):
            os.remove(temp)

    def parse_cwe_xml(self) -> Dict[str, CWE_OWASP]:
        """
        Uses `xmltodic` to parse the previously downloaded xml from cwe.mite.com :return: returns a key, value pair
        of CWE_ID and CWE Objects. Each CWE object should have an ID that matches the CWE_ID key
        """

        import xmltodict

        def get_taxonomy(taxonomy: Dict) -> Mapping:
            """

            :param taxonomy: a `dictionary` that has been parsed by `xml2dict`.
            :return: @Mapping is returned
            """
            temp = Default(taxonomy)
            return Mapping(temp.get("@Taxonomy_Name"), temp.get("Entry_ID"))

        collection_cwe: Dict[str, CWE_OWASP] = {}
        xml_path = self.downloads.joinpath("1026.xml")
        if not xml_path.exists():
            message = "Could not file the path {path}".format(path=xml_path)
            logging.error(message)
            sys.exit(message)

        with open(xml_path, 'r') as fd:
            doc = xmltodict.parse(fd.read())

            weaknesses = doc['Weakness_Catalog']["Weaknesses"]["Weakness"]
            for weakness in weaknesses:
                tax_mappings = []
                cwe = CWE_OWASP(id=weakness["@ID"], name=weakness["@Name"], description=weakness["Description"],
                                mappings=tax_mappings)

                if "Taxonomy_Mappings" in weakness.keys():
                    # Sometimes, the mapping is just a dict and not a list
                    mappings = weakness["Taxonomy_Mappings"]["Taxonomy_Mapping"]
                    if isinstance(mappings, list):
                        for taxonamy in mappings:
                            tax_mappings.append(get_taxonomy(taxonamy))
                    elif isinstance(mappings, collections.OrderedDict):
                        tax_mappings.append(get_taxonomy(mappings))
                else:
                    # Because we appended the array before hand with no items, we don't have to do anything
                    pass

                collection_cwe[str(cwe.id)] = cwe
        return collection_cwe

    def parse_asvs_csv(self, path, clazz: Generic[T]) -> List[T]:
        """

        :return: A List of DictionaryParser subclass objects are returned
        """
        # path = "{0}/ASVS-4.0.1/4.0/OWASP Application Security Verification Standard 4.0-en.csv". \
        #     format(self.get_downloads_location())
        import csv
        reader = csv.DictReader(open(path, encoding="utf-8-sig"))
        results: List[clazz] = []
        for item in reader:
            results.append(clazz.parse(item=item))
        return results

    def parse_cwe_nist(self):
        import csv
        reader = csv

    def get_asvs_init_by_cwe(self, cwe: str) -> List[ASVSInit]:
        return list(filter(lambda x: (cwe in x.asvs.cwe), self.asvs_init))

    def create_asvs_init(self, asvs_list) -> None:
        self.asvs_init = [ASVSInit(asvs) for asvs in asvs_list]

    def merge_asvsinit_mitre_nist(self, cwe_nist_list: List[CWE_NIST]):
        for cwe_nist in cwe_nist_list:
            items: List[ASVSInit] = self.get_asvs_init_by_cwe(cwe_nist.cwe_id)
            for item in items:
                item.add_CWE_NIST_to_collection(cwe_nist)


    def merge_asvsinit_mitre_cwe(self, cwe_collection: Dict[str, CWE_OWASP]) -> None:

        # Iterate all CWE mappings we have
        for key in cwe_collection.keys():
            # Match them against what ASVS was initialized with
            items: List[ASVSInit] = self.get_asvs_init_by_cwe(key)
            for item in items:
                # for each that is found, associate it with the CWE.
                item.add_cwe_owasp_map(cwe_collection.get(key))



    def write_to_file(self):
        [item.write_to_file(self.init_dir, file_name=item.asvs.item + ".md", image_path=self.image_path) for item in self.asvs_init]

    def delete_downloads(self):
        shutil.rmtree(self.downloads)

    # def __del__(self):
    #     self.delete_downloads()


if __name__ == '__main__':
    stage = Stage()
    cwe_collection = stage.parse_cwe_xml()
    asvs_list = stage.parse_asvs_csv(path="{0}/ASVS-4.0.1/4.0/OWASP Application Security Verification Standard "
                                          "4.0-en.csv".format(Stage.get_downloads_location()), clazz=ASVS)
    cwe_nist_list = stage.parse_asvs_csv(path="/Users/joubin/Git/ASVSInit/downloads/heimdall_tools-1.3.2/lib/data/cwe"
                                              "-nist-mapping.csv", clazz=CWE_NIST)
    stage.create_asvs_init(asvs_list=asvs_list)
    stage.merge_asvsinit_mitre_cwe(cwe_collection=cwe_collection)
    stage.merge_asvsinit_mitre_nist(cwe_nist_list=cwe_nist_list)
    stage.write_to_file()

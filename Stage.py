import collections
import os
import shutil
import urllib.request
from pathlib import Path
from typing import Dict, List
from zipfile import ZipFile

from datamodel.ASVS import ASVS
from datamodel.ASVSInit import ASVSInit
from datamodel.CWE import CWE
from datamodel.Taxonomy import Mapping


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
        if not self.downloads.exists(): os.mkdir(self.downloads)
        self.download_files(url="https://github.com/OWASP/ASVS/archive/v4.0.1.zip")
        self.download_files(url="https://cwe.mitre.org/data/xml/views/1026.xml.zip")
        self.init_dir = Stage.get_init_location()
        if not self.init_dir.exists(): os.mkdir(self.init_dir)
        self.image_path = self.init_dir.joinpath("images")
        if not self.image_path.exists(): os.mkdir(self.image_path)

    @staticmethod
    def get_init_location():
        return Path(os.getcwd()).joinpath("init")

    @staticmethod
    def get_downloads_location():
        return Path(os.getcwd()).joinpath("downloads")

    def download_files(self, url: str):
        if self.cwe_xml_location.exists():
            return
        print("Downloading")
        temp = self.downloads.joinpath("temp")
        urllib.request.urlretrieve(url, filename=temp)
        with ZipFile(temp, "r") as my_zip_file:
            my_zip_file.extractall(self.downloads)
        if os.path.exists(temp):
            os.remove(temp)

    def parse_cwe_xml(self) -> Dict[str, CWE]:
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

        collection_cwe: Dict[str, CWE] = {}
        with open("./downloads/1026.xml", 'r') as fd:
            doc = xmltodict.parse(fd.read())

            weaknesses = doc['Weakness_Catalog']["Weaknesses"]["Weakness"]
            for weakness in weaknesses:
                tax_mappings = []
                cwe = CWE(id=weakness["@ID"], name=weakness["@Name"], description=weakness["Description"],
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

    def parse_asvs_csv(self) -> List[ASVS]:
        path = "{0}/ASVS-4.0.1/4.0/OWASP Application Security Verification Standard 4.0-en.csv". \
            format(self.get_downloads_location())
        import csv
        reader = csv.DictReader(open(path))
        results: List[ASVS] = []
        for item in reader:
            results.append(
                ASVS(section=item["Section"], name=item["Name"], item=item["Item"], description=item["Description"],
                     l1=item["L1"], l2=item["L2"], l3=item["L3"], cwe=item["CWE"], nist=item["NIST"]))
        return results

    def map_asvs_cwe(self, cwe_collection: Dict[str, CWE], asvs_list: List[ASVS]):
        merged = []
        for asvs in asvs_list:
            if asvs.cwe is not None and asvs.cwe in cwe_collection.keys():
                merged.append(ASVSInit(asvs, cwe_collection[asvs.cwe]))
            else:
                merged.append(ASVSInit(asvs, CWE()))

        return merged

    def write_to_file(self, x: List[ASVSInit]):
        [item.write_to_file(self.init_dir, file_name=item.asvs.item + ".md", image_path=self.image_path) for item in x]

    def delete_downloads(self):
        shutil.rmtree(self.downloads)


if __name__ == '__main__':
    stage = Stage()
    cwe_collection = stage.parse_cwe_xml()
    asvs_list = stage.parse_asvs_csv()
    merged = stage.map_asvs_cwe(cwe_collection=cwe_collection, asvs_list=asvs_list)
    stage.write_to_file(x=merged)

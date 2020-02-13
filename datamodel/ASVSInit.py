import urllib
from pathlib import Path
from typing import List
from urllib.error import HTTPError

from datamodel.ASVS import ASVS
from datamodel.CWE import CWE
from datamodel.CWE_OWASP import CWE_OWASP
import urllib.request
from urllib.request import ProxyHandler, build_opener, install_opener
from urllib.parse import quote as encode

from datamodel.CWE_NIST import CWE_NIST
from datamodel.NISTPublication import NISTPublication
from datamodel.NISTPublicationCollection import NISTPublicationCollection


class ASVSInit:
    proxy = ProxyHandler({})
    opener = build_opener(proxy)
    opener.addheaders = [('User-Agent','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30')]
    """Because the bahavior of the mitre site is not common when the user header is the generic urllib"""
    install_opener(opener)

    def __init__(self, asvs: ASVS):
        self.asvs = asvs
        self.cwe: List[CWE] = []
        self.nist: NISTPublicationCollection = NISTPublicationCollection()
        self.cwe_owasp_mapping: List[CWE_OWASP] = []
        self.__init_with_self_nist_publications()

    def __init_with_self_nist_publications(self):
        for publications in self.asvs.nist_publications:
            self.nist.add_publication_to_collection(publication=publications)

    def add_cwe_owasp_map(self, mitre_cwe_map: CWE_OWASP):
        self.cwe_owasp_mapping.append(mitre_cwe_map)

    def add_CWE_NIST_to_collection(self, nist: CWE_NIST):
        self.nist.add_cwenist_to_collection(nist)

    def get_shield(self, left: str, right: str, color: str, image_dir: Path):
        right = right.replace("/", " ")
        left = left.replace("/", " ")
        def make_shiled_url():
            return "https://img.shields.io/badge/{left}-{right}-{color}.svg".format(left=encode(left),
                                                                                    right=encode(right),
                                                                                    color=encode(color))

        file_name = image_dir.joinpath("{left}-{right}-{color}.svg".format(left=left,
                                                                           right=right,
                                                                           color=color).replace(" ", "_"))

        url = make_shiled_url()
        if not file_name.exists():
            try:
                urllib.request.urlretrieve(url,
                                           filename=file_name)
            except HTTPError as e:
                print(e)

        return file_name.relative_to(image_dir.parent)


    def write_to_file(self, md_path: Path, file_name: str, image_path: Path):
        def nl():
            return "\n"

        asvs_description = self.asvs.description
        asvs_item = self.get_shield(left="ASVS", right=self.asvs.item, color="blue", image_dir=image_path)
        asvs_section = self.get_shield(left="", right=self.asvs.section, color="green", image_dir=image_path)

        cwe_id = self.get_shield(left="CWE", right=self.asvs.cwe, color="red", image_dir=image_path)
        nist_shields = []
        for nist_publication in self.asvs.nist_publications:
            for nist in nist_publication.nist:
                nist_shields.append(self.get_shield(left=nist_publication.publication, right=nist.id, color="important", image_dir=image_path))

        owasp_shields = []
        for owasp in self.cwe_owasp_mapping:
            owasp_shields.append(self.get_shield(left=owasp.get_latest_owasp_source_id()[0],
                                right=owasp.get_latest_owasp_source_id()[1], color="lightgrey",
                                image_dir=image_path),)


        document = ""
        document += "### ASVS"
        document += nl()
        document += "![Section](./{asvs_section})".format(asvs_section=asvs_section)
        document += "![ASVS](./{asvs_item})".format(asvs_item=asvs_item)
        document += "![CWE](./{cwe_id})".format(cwe_id=cwe_id)
        for nist_shield in nist_shields:
            document += "![NIST](./{nist_id})".format(nist_id=nist_shield)
        for owasp_shield in owasp_shields:
            document += "![Top 10](./{owasp})".format(owasp=owasp_shield)

        document += nl()*2

        document += asvs_description

        document += nl()*2

        document += """


| L1       |    L2    |       L3 |
| -------- | :------: | -------: |
| {l1:^8s} | {l2:^8s} | {l3:^8s} |


### Tested

### Validation

### Comments

        """.format(l1=self.asvs.l1, l2=self.asvs.l2, l3=self.asvs.l3)
        with open(md_path.joinpath(file_name).as_posix(), 'w+') as file:
            file.write(document)

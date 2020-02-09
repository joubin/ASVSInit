import urllib
from pathlib import Path

from datamodel.ASVS import ASVS
from datamodel.CWE import CWE
import urllib.request
from urllib.request import ProxyHandler, build_opener, install_opener
from urllib.parse import quote as encode

class ASVSInit:
    proxy = ProxyHandler({})
    opener = build_opener(proxy)
    opener.addheaders = [('User-Agent','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/603.1.30 (KHTML, like Gecko) Version/10.1 Safari/603.1.30')]
    install_opener(opener)

    def __init__(self, asvs: ASVS, cwe: CWE):
        self.asvs = asvs
        self.cwe = cwe

    def get_shield(self, left: str, right: str, color: str, image_dir: Path):
        right = right.replace("/", " ")
        left = left.replace("/", " ")
        def make_shiled_url():
            return "https://img.shields.io/badge/{left}-{right}-{color}.svg".format(left=encode(left),
                                                                                    right=encode(right),
                                                                                    color=encode(color))

        file_name = image_dir.joinpath("{left}-{right}-{color}.svg".format(left=left,
                                                                           right=right,
                                                                           color=
                                                                               color))
        url = make_shiled_url()
        if not file_name.exists():
            urllib.request.urlretrieve(url,
                                       filename=file_name)
        print(".", end="")
        return file_name.relative_to(image_dir.parent)


    def write_to_file(self, md_path: Path, file_name: str, image_path: Path):


        data = """### ASVS
![Section]({asvs_section})![ASVS]({asvs_item})![CWE]({cwe_id})![NIST]({nist_id})![Top 10]({owasp})

{asvs_description}


| L1       |    L2    |       L3 |
| -------- | :------: | -------: |
| {l1:^8s} | {l2:^8s} | {l3:^8s} |


### Tested

### Validation

### Comments

        """.format(asvs_description=self.asvs.description,
                   asvs_item=self.get_shield(left="ASVS", right=self.asvs.item, color="blue", image_dir=image_path),
                   asvs_section=self.get_shield(left="", right=self.asvs.section, color="green", image_dir=image_path),
                   cwe_id=self.get_shield(left="CWE", right=self.cwe.id, color="red", image_dir=image_path),
                   nist_id=self.get_shield(left="NIST", right=self.asvs.nist, color="important", image_dir=image_path),
                   owasp=self.get_shield(left=self.cwe.get_latest_owasp_source_id()[0], right=self.cwe.get_latest_owasp_source_id()[1], color="lightgrey", image_dir=image_path),
                   l1=self.asvs.l1,
                   l2=self.asvs.l2,
                   l3=self.asvs.l3)
        with open(md_path.joinpath(file_name).as_posix(), 'w+') as file:
            file.write(data)

from pathlib import Path

from datamodel.ASVS import ASVS
from datamodel.CWE import CWE
import urllib.parse

class ASVSInit:
    def __init__(self, asvs: ASVS, cwe: CWE):
        self.asvs = asvs
        self.cwe = cwe

    def write_to_file(self, path: Path, file_name: str):
        encode = urllib.parse.quote
        latest_owasp_source, latest_owasp_id = (self.cwe.get_latest_owasp().source,
                                                self.cwe.get_latest_owasp().id) if self.cwe.get_latest_owasp() is not \
                                                                                   None else ("", "")
        latest_owasp_source = encode(latest_owasp_source)

        data = """### {asvs_item} 
{asvs_description}

![Section]({shield_url}{asvs_section}-green.svg)![ASVS]({shield_url}ASVS-{asvs_item}-blue.svg)![CWE]({shield_url}CWE-{cwe_id}-red.svg)![NIST]({shield_url}NIST-{nist_id}-important.svg)![Top 10]({shield_url}{owasp}-{owasp_id}-lightgray.svg)

| L1| L2| L3|
| --|:--:|-:|
| {l1} | {l2} | {l3} |

### Tested

### Validation

### Comments

        """.format(asvs_description=self.asvs.description, asvs_item=self.asvs.item, asvs_section=self.asvs.section,
                   shield_url="https://img.shields.io/badge/", cwe_id=self.cwe.id, nist_id=encode(self.asvs.nist),
                   owasp=latest_owasp_source, owasp_id=latest_owasp_id, l1=self.asvs.l1, l2=self.asvs.l2, l3=self.asvs.l3)
        with open(path.joinpath(file_name).as_posix(), 'w+') as file:
            file.write(data)

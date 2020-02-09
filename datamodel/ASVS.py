class ASVS:

    def __init__(self, section: str, name: str, item: str, description: str, l1: str, l2: str, l3: str, cwe: str,
                 nist: str):
        self.section = section
        self.name = name
        self.item = item
        self.description = description
        self.l1 = l1
        self.l3 = l3
        self.l2 = l2
        self.cwe = cwe
        self.nist = nist

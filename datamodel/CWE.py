from datamodel.Taxonomy import Mapping


class CWE:

    def __init__(self, id: str = "", name: str = "", description: str = "", mappings=None):
        if mappings is None:
            mappings = [Mapping()]
        self.name = name.strip()
        self.mappings = mappings
        self.description = description.strip()
        self.id = id.strip()

    def get_latest_owasp(self):
        """

        :return: The latest OWASP item if any; otherwise returns none.
        """
        list = []
        for item in self.mappings:
            if "OWASP" in item.source:
                list.append(item)
        list.sort(key=lambda x: x.source, reverse=True)
        return next(iter(list), None)

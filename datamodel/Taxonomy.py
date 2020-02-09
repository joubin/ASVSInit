class Mapping(object):
    def __init__(self, source: str = "", id: str = ""):
        self.source = source.strip() if source is not None else ""
        self.id = id.strip() if id is not None else ""

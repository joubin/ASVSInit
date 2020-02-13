import abc


class DictionaryParser(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def parse(cls, item):
        raise NotImplementedError

    @abc.abstractmethod
    def merge_data(self, data):
        raise NotImplementedError

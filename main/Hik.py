from abc import ABC, abstractmethod


class Hik(ABC):
    @abstractmethod
    def detect_suitability(self, ip: str, port: str) -> bool:
        """detect, if the device version is suitable for this particular module """
        pass

    @abstractmethod
    def perform_auth(self, ip:str, port: str, username: str, password: str) -> bool:
        """perform authentication, return True if successful"""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """return version number of the device handled by this module"""
        pass

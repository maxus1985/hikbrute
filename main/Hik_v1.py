from asyncio.log import logger

import requests

from main.Hik import Hik
contentType = "application/xml"


class HikV1(Hik):
    auth_link = "http://{ip}:{port}/ISAPI/Security/challenge"
    auth_payload = """<?xml version="1.0" encoding="utf-8"?>"""

    def get_version(self) -> str:
        return "v1"

    def detect_suitability(self, ip: str, port: str) -> bool:
        """detect, if the device version is suitable for this particular module """
        link = self.auth_link.format(ip=ip, port=port)

        headers = {'Content-Type': self.contentType, 'Accept':self.contentType}

        result = requests.post(link, headers=headers)
        logger.debug(f"{self.get_version()} trying to access {link}, result {result.status_code}")
        if result.status_code != 200:
            return False

        return "key" in result.text


    def perform_auth(self, ip:str, port:str, username: str, password: str) -> bool:
        """perform authentication, return True if successful"""
        return True

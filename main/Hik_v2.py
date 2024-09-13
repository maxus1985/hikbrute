from asyncio.log import logger

import requests

from main.Hik import Hik


class HikV2(Hik):
    auth_link = "http://{ip}:{port}/ISAPI/Security/sessionLogin/capabilities?username={username}"
    auth_payload = """<?xml version="1.0" encoding="utf-8"?>"""
    contentType = "application/xml"

    def get_version(self) -> str:
        return "v2"

    def detect_suitability(self, ip: str, port: str) -> bool:
        """detect, if the device version is suitable for this particular module """
        link = self.auth_link.format(ip=ip, port=port, username="dummy")
        headers = {'Content-Type': self.contentType, 'Accept':self.contentType}

        result = requests.post(link, headers=headers)
        logger.debug(f"{self.get_version()} trying to access {link}, result {result.status_code}")
        if result.status_code != 200:
            return False

        return ("sessionId" in result.text) and ("challenge" in result.text) and ("iterations" in result.text) and ("isIrreversible" in result.text)

    def perform_auth(self, ip:str, port:str, username: str, password: str) -> bool:
        """perform authentication, return True if successful"""
        return True

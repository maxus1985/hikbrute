from typing import Union

from main.Hik_v1 import HikV1
from main.Hik_v2 import HikV2


def detect_hik_version(ip: str, port: str) -> Union[HikV1, HikV2, None]:
    if HikV1().detect_suitability(ip, port):
        return HikV1()
    elif HikV2().detect_suitability(ip, port):
        return HikV2()
    else:
        return None

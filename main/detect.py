from typing import Union

import Hik_v1
import Hik_v2
from main.Hik_v1 import HikV1
from main.Hik_v2 import HikV2


def detect_hik_version(ip: str, port: str) -> Union[HikV1, HikV2, None]:
    if Hik_v1.HikV1().detect_suitability(ip, port):
        return Hik_v1.HikV1()
    elif Hik_v2.HikV2().detect_suitability(ip, port):
        return Hik_v2.HikV2()
    else:
        return None

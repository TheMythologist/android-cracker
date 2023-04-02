import xml.etree.ElementTree as ET

from cracker.exception import InvalidFileException
from cracker.policy import DevicePolicy, PasswordProperty


def retrieve_policy(xml_data: str) -> DevicePolicy:
    root = ET.fromstring(xml_data)
    if (active_password := root.find("active-password")) is None:
        raise InvalidFileException("Invalid device_policies.xml file")
    return DevicePolicy(
        int(active_password.attrib["length"]),
        PasswordProperty(
            int(active_password.attrib["uppercase"]),
            int(active_password.attrib["lowercase"]),
            int(active_password.attrib["numeric"]),
            int(active_password.attrib["symbols"]),
        ),
    )

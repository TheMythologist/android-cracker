import xml.etree.ElementTree as ET

from cracker.exception import InvalidFileException


def retrieve_length(xml_data: str) -> int:
    root = ET.fromstring(xml_data)
    if (active_password := root.find("active-password")) is None:
        raise InvalidFileException("Invalid device_policies.xml file")
    return int(active_password.attrib["length"])

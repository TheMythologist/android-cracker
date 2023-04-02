from pathlib import Path

import pytest

from cracker.exception import InvalidFileException
from cracker.parsers.device_policies import retrieve_length


def test_device_policies():
    assert (
        retrieve_length(Path("sample/device_policies/device_policies.xml").read_text())
        == 4
    )


def test_bad_device_policies():
    with pytest.raises(
        InvalidFileException,
        match="Invalid device_policies.xml file",
    ):
        retrieve_length(
            Path("sample/device_policies/bad_device_policies.xml").read_text()
        )

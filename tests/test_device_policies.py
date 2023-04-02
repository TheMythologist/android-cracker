from pathlib import Path

import pytest

from cracker.exception import InvalidFileException
from cracker.parsers.device_policies import retrieve_policy
from cracker.policy import DevicePolicy, PasswordProperty


def test_device_policies() -> None:
    assert retrieve_policy(
        Path("sample/device_policies/device_policies.xml").read_text()
    ) == DevicePolicy(4, PasswordProperty(0, 0, 4, 0))


def test_bad_device_policies() -> None:
    with pytest.raises(
        InvalidFileException,
        match="Invalid device_policies.xml file",
    ):
        retrieve_policy(
            Path("sample/device_policies/bad_device_policies.xml").read_text()
        )

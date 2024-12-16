import os

import pytest

from py7zr import SevenZipFile
from py7zr.exceptions import Bad7zFile
from py7zr.helpers import check_archive_path, get_sanitized_output_path
from py7zr.properties import FILTER_LZMA2, PRESET_DEFAULT

testdata_path = os.path.join(os.path.dirname(__file__), "data")


@pytest.mark.misc
def test_check_archive_path():
    bad_path = "../../.../../../../../../tmp/evil.sh"
    assert not check_archive_path(bad_path)


@pytest.mark.misc
def test_get_sanitized_output_path_1(tmp_path):
    bad_path = "../../.../../../../../../tmp/evil.sh"
    with pytest.raises(Bad7zFile):
        get_sanitized_output_path(bad_path, tmp_path)


@pytest.mark.misc
def test_get_sanitized_output_path_2(tmp_path):
    good_path = "good.sh"
    expected = tmp_path.joinpath(good_path)
    assert expected == get_sanitized_output_path(good_path, tmp_path)


@pytest.mark.misc
def test_extract_path_traversal_attack(tmp_path):
    my_filters = [
        {"id": FILTER_LZMA2, "preset": PRESET_DEFAULT},
    ]
    target = tmp_path.joinpath("target.7z")
    good_data = b"#!/bin/sh\necho good\n"
    good_path = "good.sh"
    bad_data = b"!#/bin/sh\necho bad\n"
    bad_path = "../../.../../../../../../tmp/evil.sh"
    with SevenZipFile(target, "w", filters=my_filters) as archive:
        archive.writestr(good_data, good_path)
        archive._writestr(bad_data, bad_path)  # bypass a path check
    with pytest.raises(Bad7zFile):
        with SevenZipFile(target, "r") as archive:
            archive.extractall(path=tmp_path)

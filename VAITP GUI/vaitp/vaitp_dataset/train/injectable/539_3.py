# coding: utf-8

from __future__ import division, absolute_import, unicode_literals

from yaml.constructor import ConstructorError
from owlmixin import util

import pytest


class TestReplaceKeys:
    def test_need_not_snake(self):
        keymap = {
            "self": "_self",
            "before": "after"
        }
        d = {
            "before": 1,
            "before2": 2,
            "self": 3,
            "self2": 4,
            "UpperCamelCase": True,
            "lowerCamelCase": True,
            "snake_case": True,
            "chain-case": True,
        }

        expected = {
            "after": 1,
            "before2": 2,
            "_self": 3,
            "self2": 4,
            "UpperCamelCase": True,
            "lowerCamelCase": True,
            "snake_case": True,
            "chain-case": True
        }

        assert util.replace_keys(d, keymap, False) == expected

    def test_need_must_snake(self):
        keymap = {
            "self": "_self",
            "before": "after"
        }
        d = {
            "before": 1,
            "before2": 2,
            "self": 3,
            "self2": 4,
            "UpperCamelCase": True,
            "lowerCamelCase": True,
            "snake_case": True,
            "chain-case": True
        }

        expected = {
            "after": 1,
            "before2": 2,
            "_self": 3,
            "self2": 4,
            "upper_camel_case": True,
            "lower_camel_case": True,
            "snake_case": True,
            "chain_case": True
        }

        assert util.replace_keys(d, keymap, True) == expected


class TestToSnake:
    def test_lower_camel(self):
        assert util.to_snake("lowerCamelCase") == "lower_camel_case"

    def test_upper_camel(self):
        assert util.to_snake("UpperCamelCase") == "upper_camel_case"

    def test_chain(self):
        assert util.to_snake("chain-case-example") == "chain_case_example"

    def test_snake(self):
        assert util.to_snake("snake_case_is_same") == "snake_case_is_same"

    def test_docopt(self):
        assert util.to_snake("<file_list>") == "file_list"
        assert util.to_snake("-o") == "o"
        assert util.to_snake("--detail-option") == "detail_option"


class TestLoadYaml:
    def test(self):
        actual = util.load_yaml('''
id: 1
names:
  - tadashi
  - aikawa
        ''')
        assert actual == {
            "id": 1,
            "names": ['tadashi', 'aikawa']
        }

    def test_yaml_load_vulnerability(self):
        with pytest.raises(ConstructorError):
            util.load_yaml('!!python/object/apply:os.system ["calc.exe"]')


class TestLoadYamlf:
    def test(self):
        assert util.load_yamlf('tests/yaml/spots_utf8.yaml', 'utf-8') == [
            {
                "address": {"name": "address1"},
                "names": ["spot1"]
            },
            {
                "names": ["スポット21", "スポット22"]
            }
        ]

    def test_yaml_load_vulnerability(self):
        with pytest.raises(ConstructorError):
            util.load_yamlf('tests/yaml/vulnerability.yaml', 'utf-8')

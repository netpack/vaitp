```python
import os
from io import BytesIO
from unittest import mock
from unittest.mock import MagicMock
from zipfile import ZipFile

import pytest

from fides.api.common_exceptions import NoSuchSaaSRequestOverrideException
from fides.api.models.custom_connector_template import CustomConnectorTemplate
from fides.api.schemas.saas.connector_template import ConnectorTemplate
from fides.api.service.authentication.authentication_strategy import (
    AuthenticationStrategy,
)
from fides.api.service.connectors.saas.connector_registry_service import (
    ConnectorRegistry,
    CustomConnectorTemplateLoader,
    FileConnectorTemplateLoader,
)
from fides.api.service.saas_request.saas_request_override_factory import (
    SaaSRequestOverrideFactory,
    SaaSRequestType,
)
from fides.api.util.saas_util import (
    encode_file_contents,
    load_config_from_string,
    load_yaml_as_string,
    replace_version,
)
from fides.config import CONFIG
from tests.ops.test_helpers.saas_test_utils import create_zip_file


class TestFileConnectorTemplateLoader:
    def test_file_connector_template_loader(self):
        loader = FileConnectorTemplateLoader()
        connector_templates = loader.get_connector_templates()

        assert connector_templates

        mailchimp_connector = connector_templates.get("mailchimp")
        assert mailchimp_connector

        assert mailchimp_connector.config == load_yaml_as_string(
            "data/saas/config/mailchimp_config.yml"
        )
        assert mailchimp_connector.dataset == load_yaml_as_string(
            "data/saas/dataset/mailchimp_dataset.yml"
        )
        assert mailchimp_connector.icon == encode_file_contents(
            "data/saas/icon/mailchimp.svg"
        )
        assert mailchimp_connector.human_readable == "Mailchimp"

    def test_file_connector_template_loader_connector_not_found(self):
        connector_templates = FileConnectorTemplateLoader.get_connector_templates()

        assert connector_templates.get("not_found") is None


class TestCustomConnectorTemplateLoader:
    @pytest.fixture(autouse=True)
    def reset_connector_template_loaders(self):
        """
        Resets the loader singleton instances before each test
        """
        FileConnectorTemplateLoader._instance = None
        CustomConnectorTemplateLoader._instance = None

    @pytest.fixture
    def zendesk_config(self) -> str:
        return load_yaml_as_string("data/saas/config/zendesk_config.yml")

    @pytest.fixture
    def zendesk_dataset(self) -> str:
        return load_yaml_as_string("data/saas/dataset/zendesk_dataset.yml")

    @pytest.fixture
    def replaceable_zendesk_config(self) -> str:
        return load_yaml_as_string(
            "tests/fixtures/saas/test_data/replaceable_zendesk_config.yml"
        )

    @pytest.fixture
    def replaceable_planet_express_config(self) -> str:
        return load_yaml_as_string(
            "tests/fixtures/saas/test_data/planet_express/replaceable_planet_express_config.yml"
        )

    @pytest.fixture
    def replaceable_zendesk_zip(
        self, replaceable_zendesk_config, zendesk_dataset
    ) -> BytesIO:
        return create_zip_file(
            {
                "config.yml": replace_version(replaceable_zendesk_config, "0.0.0"),
                "dataset.yml": zendesk_dataset,
            }
        )

    @pytest.fixture
    def non_replaceable_zendesk_zip(self, zendesk_config, zendesk_dataset) -> BytesIO:
        return create_zip_file(
            {
                "config.yml": replace_version(zendesk_config, "0.0.0"),
                "dataset.yml": zendesk_dataset,
            }
        )

    @pytest.fixture
    def replaceable_planet_express_zip(
        self,
        replaceable_planet_express_config,
        planet_express_dataset,
        planet_express_icon,
    ) -> BytesIO:
        return create_zip_file(
            {
                "config.yml": replaceable_planet_express_config,
                "dataset.yml": planet_express_dataset,
                "icon.svg": planet_express_icon,
            }
        )

    @pytest.fixture
    def non_replaceable_zendesk_zip(self, zendesk_config, zendesk_dataset) -> BytesIO:
        return create_zip_file(
            {
                "config.yml": replace_version(zendesk_config, "0.0.0"),
                "dataset.yml": zendesk_dataset,
            }
        )

    def test_custom_connector_template_loader_no_templates(self):
        connector_templates = CustomConnectorTemplateLoader.get_connector_templates()
        assert connector_templates == {}

    @mock.patch(
        "fides.api.models.custom_connector_template.CustomConnectorTemplate.all"
    )
    def test_custom_connector_template_loader_invalid_template(
        self,
        mock_all: MagicMock,
        planet_express_dataset,
        planet_express_icon,
    ):
        mock_all.return_value = [
            CustomConnectorTemplate(
                key="planet_express",
                name="Planet Express",
                config="planet_express_config",
                dataset=planet_express_dataset,
                icon=planet_express_icon,
            )
        ]

        connector_templates = CustomConnectorTemplateLoader.get_connector_templates()
        assert connector_templates == {}

    @mock.patch(
        "fides.api.models.custom_connector_template.CustomConnectorTemplate.all"
    )
    def test_custom_connector_template_loader(
        self,
        mock_all: MagicMock,
        planet_express_config,
        planet_express_dataset,
        planet_express_icon,
    ):
        mock_all.return_value = [
            CustomConnectorTemplate(
                key="planet_express",
                name="Planet Express",
                config=planet_express_config,
                dataset=planet_express_dataset,
                icon=planet_express_icon,
            )
        ]

        # load custom connector templates from the database
        connector_templates = CustomConnectorTemplateLoader.get_connector_templates()

        # verify that the template in the registry is the same as the one in the database
        assert connector_templates == {
            "planet_express": ConnectorTemplate(
                config=planet_express_config,
                dataset=planet_express_dataset,
                icon=planet_express_icon,
                human_readable="Planet Express",
            )
        }

    @mock.patch(
        "fides.api.models.custom_connector_template.CustomConnectorTemplate.all"
    )
    def test_loaders_have_separate_instances(
        self,
        mock_all: MagicMock,
        planet_express_config,
        planet_express_dataset,
        planet_express_icon,
    ):
        mock_all.return_value = [
            CustomConnectorTemplate(
                key="planet_express",
                name="Planet Express",
                config=planet_express_config,
                dataset=planet_express_dataset,
                icon=planet_express_icon,
            )
        ]

        # load custom connector templates from the database
        file_connector_templates = FileConnectorTemplateLoader.get_connector_templates()
        custom_connector_templates = (
            CustomConnectorTemplateLoader.get_connector_templates()
        )

        assert file_connector_templates != custom_connector_templates

    @mock.patch(
        "fides.api.models.custom_connector_template.CustomConnectorTemplate.create_or_update"
    )
    def test_custom_connector_save_template(
        self,
        mock_create_or_update: MagicMock,
        planet_express_config,
        planet_express_dataset,
        planet_express_icon,
    ):
        db = MagicMock()
        url = CONFIG["FIDES_CUSTOM_CONNECTOR_TEMPLATES_URL"]
        file_name = f"{url}/planet_express.zip"
        zip_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_name)
        Custom
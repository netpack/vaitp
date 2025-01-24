```python
from pydantic import ValidationError
from pydantic.error_wrappers import ErrorWrapper

import openapi_python_client.schema as oai
from openapi_python_client import GeneratorError, utils
from openapi_python_client.parser.errors import ParseError

MODULE_NAME = "openapi_python_client.parser.openapi"


class TestGeneratorData:
    def test_from_dict(self, mocker):
        Schemas = mocker.patch(f"{MODULE_NAME}.Schemas")
        EndpointCollection = mocker.patch(f"{MODULE_NAME}.EndpointCollection")
        OpenAPI = mocker.patch(f"{MODULE_NAME}.oai.OpenAPI")
        OpenAPI.parse_obj.return_value = openapi = mocker.MagicMock()

        in_dict = mocker.MagicMock()
        get_all_enums = mocker.patch(f"{MODULE_NAME}.EnumProperty.get_all_enums")

        from openapi_python_client.parser.openapi import GeneratorData

        generator_data = GeneratorData.from_dict(in_dict)

        OpenAPI.parse_obj.assert_called_once_with(in_dict)
        Schemas.build.assert_called_once_with(schemas=openapi.components.schemas)
        EndpointCollection.from_data.assert_called_once_with(data=openapi.paths)
        get_all_enums.assert_called_once_with()
        assert generator_data == GeneratorData(
            title=openapi.info.title,
            description=openapi.info.description,
            version=openapi.info.version,
            endpoint_collections_by_tag=EndpointCollection.from_data.return_value,
            schemas=Schemas.build.return_value,
            enums=get_all_enums.return_value,
        )

        # Test no components
        openapi.components = None
        Schemas.build.reset_mock()

        generator_data = GeneratorData.from_dict(in_dict)

        Schemas.build.assert_not_called()
        assert generator_data.schemas == Schemas()

    def test_from_dict_invalid_schema(self, mocker):
        Schemas = mocker.patch(f"{MODULE_NAME}.Schemas")

        in_dict = {}

        from openapi_python_client.parser.openapi import GeneratorData

        generator_data = GeneratorData.from_dict(in_dict)

        assert generator_data == GeneratorError(
            header="Failed to parse OpenAPI document",
            detail=(
                "2 validation errors for OpenAPI\n"
                "info\n"
                "  field required (type=value_error.missing)\n"
                "paths\n"
                "  field required (type=value_error.missing)"
            ),
        )
        Schemas.build.assert_not_called()
        Schemas.assert_not_called()


class TestModel:
    def test_from_data(self, mocker):
        from openapi_python_client.parser.properties import Property

        in_data = oai.Schema.construct(
            title=mocker.MagicMock(),
            description=mocker.MagicMock(),
            required=["RequiredEnum"],
            properties={"RequiredEnum": mocker.MagicMock(), "OptionalDateTime": mocker.MagicMock(),},
        )
        required_property = mocker.MagicMock(autospec=Property)
        required_imports = mocker.MagicMock()
        required_property.get_imports.return_value = {required_imports}
        optional_property = mocker.MagicMock(autospec=Property)
        optional_imports = mocker.MagicMock()
        optional_property.get_imports.return_value = {optional_imports}
        property_from_data = mocker.patch(
            f"{MODULE_NAME}.property_from_data", side_effect=[required_property, optional_property],
        )
        from_ref = mocker.patch(f"{MODULE_NAME}.Reference.from_ref")

        from openapi_python_client.parser.openapi import Model

        result = Model.from_data(data=in_data, name=mocker.MagicMock())

        from_ref.assert_called_once_with(in_data.title)
        property_from_data.assert_has_calls(
            [
                mocker.call(name="RequiredEnum", required=True, data=in_data.properties["RequiredEnum"]),
                mocker.call(name="OptionalDateTime", required=False, data=in_data.properties["OptionalDateTime"]),
            ]
        )
        required_property.get_imports.assert_called_once_with(prefix="")
        optional_property.get_imports.assert_called_once_with(prefix="")
        assert result == Model(
            reference=from_ref(),
            required_properties=[required_property],
            optional_properties=[optional_property],
            relative_imports={required_imports, optional_imports,},
            description=in_data.description,
        )

    def test_from_data_property_parse_error(self, mocker):
        in_data = oai.Schema.construct(
            title=mocker.MagicMock(),
            description=mocker.MagicMock(),
            required=["RequiredEnum"],
            properties={"RequiredEnum": mocker.MagicMock(), "OptionalDateTime": mocker.MagicMock(),},
        )
        parse_error = ParseError(data=mocker.MagicMock())
        property_from_data = mocker.patch(f"{MODULE_NAME}.property_from_data", return_value=parse_error,)
        from_ref = mocker.patch(f"{MODULE_NAME}.Reference.from_ref")

        from openapi_python_client.parser.openapi import Model

        result = Model.from_data(data=in_data, name=mocker.MagicMock())

        from_ref.assert_called_once_with(in_data.title)
        property_from_data.assert_called_once_with(
            name="RequiredEnum", required=True, data=in_data.properties["RequiredEnum"]
        )

        assert result == parse_error


class TestSchemas:
    def test_build(self, mocker):
        from_data = mocker.patch(f"{MODULE_NAME}.Model.from_data")
        in_data = {"1": mocker.MagicMock(enum=None), "2": mocker.MagicMock(enum=None), "3": mocker.MagicMock(enum=None)}
        schema_1 = mocker.MagicMock()
        schema_2 = mocker.MagicMock()
        error = ParseError()
        from_data.side_effect = [schema_1, schema_2, error]

        from openapi_python_client.parser.openapi import Schemas

        result = Schemas.build(schemas=in_data)

        from_data.assert_has_calls([mocker.call(data=value, name=name) for (name, value) in in_data.items()])
        assert result == Schemas(
            models={schema_1.reference.class_name: schema_1, schema_2.reference.class_name: schema_2,}, errors=[error]
        )

    def test_build_parse_error_on_reference(self):
        from openapi_python_client.parser.openapi import Schemas

        ref_schema = oai.Reference.construct()
        in_data = {1: ref_schema}
        result = Schemas.build(schemas=in_data)
        assert result.errors[0] == ParseError(data=ref_schema, detail="Reference schemas are not supported.")

    def test_build_enums(self, mocker):
        from openapi_python_client.parser.openapi import Schemas

        from_data = mocker.patch(f"{MODULE_NAME}.Model.from_data")
        enum_property = mocker.patch(f"{MODULE_NAME}.EnumProperty")
        in_data = {"1": mocker.MagicMock(enum=["val1", "val2", "val3"])}

        Schemas.build(schemas=in_data)

        enum_property.assert_called()
        from_data.assert_not_called()

    def test_add_enums(self, mocker):
        from openapi_python_client.parser.openapi import Schemas

        error = ParseError(data=mocker.MagicMock())
        enum_property = mocker.patch(f"{MODULE_NAME}.EnumProperty", return_value=error)
        data = ["val1", "val2", "val3"]
        schemas = Schemas()
        schemas.enum_collection = mocker.MagicMock()

        result = schemas.add_enums(data=data
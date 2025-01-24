```python
import dataclasses
import datetime
import enum
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import typing
import weakref
from abc import ABC, abstractmethod
from pathlib import Path, PurePath
from typing import (
    Any,
    BinaryIO,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Set,
    TextIO,
    Tuple,
    Type,
    TypedDict,
    Union,
)

import ops
import ops.pebble as pebble
from ops._private import timeconv, yaml
from ops.jujuversion import JujuVersion

# a k8s spec is a mapping from names/"types" to json/yaml spec objects
K8sSpec = Mapping[str, Any]

_StorageDictType = Dict[str, Optional[List['Storage']]]
_BindingDictType = Dict[Union[str, 'Relation'], 'Binding']

_StatusDict = TypedDict('_StatusDict', {'status': str, 'message': str})

# mapping from relation name to a list of relation objects
_RelationMapping_Raw = Dict[str, Optional[List['Relation']]]
# mapping from container name to container metadata
_ContainerMeta_Raw = Dict[str, 'ops.charm.ContainerMeta']

# relation data is a string key: string value mapping so far as the
# controller is concerned
_RelationDataContent_Raw = Dict[str, str]
UnitOrApplicationType = Union[Type['Unit'], Type['Application']]

_AddressDict = TypedDict(
    '_AddressDict',
    {
        'address': str,  # Juju < 2.9
        'value': str,  # Juju >= 2.9
        'cidr': str,
    },
)
_BindAddressDict = TypedDict(
    '_BindAddressDict', {'interface-name': str, 'addresses': List[_AddressDict]}
)
_NetworkDict = TypedDict(
    '_NetworkDict',
    {
        'bind-addresses': List[_BindAddressDict],
        'ingress-addresses': List[str],
        'egress-subnets': List[str],
    },
)


logger = logging.getLogger(__name__)

MAX_LOG_LINE_LEN = 131071  # Max length of strings to pass to subshell.


class Model:
    """Represents the Juju Model as seen from this unit.

    This should not be instantiated directly by Charmers, but can be accessed
    as ``self.model`` from any class that derives from :class:`Object`.
    """

    def __init__(
        self,
        meta: 'ops.charm.CharmMeta',
        backend: '_ModelBackend',
        broken_relation_id: Optional[int] = None,
    ):
        self._cache = _ModelCache(meta, backend)
        self._backend = backend
        self._unit = self.get_unit(self._backend.unit_name)
        relations: Dict[str, ops.RelationMeta] = meta.relations
        self._relations = RelationMapping(
            relations, self.unit, self._backend, self._cache, broken_relation_id=broken_relation_id
        )
        self._config = ConfigData(self._backend)
        resources: Iterable[str] = meta.resources
        self._resources = Resources(list(resources), self._backend)
        self._pod = Pod(self._backend)
        storages: Iterable[str] = meta.storages
        self._storages = StorageMapping(list(storages), self._backend)
        self._bindings = BindingMapping(self._backend)

    @property
    def unit(self) -> 'Unit':
        """The unit that is running this code.

        Use :meth:`get_unit` to get an arbitrary unit by name.
        """
        return self._unit

    @property
    def app(self) -> 'Application':
        """The application this unit is a part of.

        Use :meth:`get_app` to get an arbitrary application by name.
        """
        return self._unit.app

    @property
    def relations(self) -> 'RelationMapping':
        """Mapping of endpoint to list of :class:`Relation`.

        Answers the question "what am I currently integrated with".
        See also :meth:`.get_relation`.

        In a ``relation-broken`` event, the broken relation is excluded from
        this list.
        """
        return self._relations

    @property
    def config(self) -> 'ConfigData':
        """Return a mapping of config for the current application."""
        return self._config

    @property
    def resources(self) -> 'Resources':
        """Access to resources for this charm.

        Use ``model.resources.fetch(resource_name)`` to get the path on disk
        where the resource can be found.
        """
        return self._resources

    @property
    def storages(self) -> 'StorageMapping':
        """Mapping of storage_name to :class:`Storage` as defined in metadata.yaml."""
        return self._storages

    @property
    def pod(self) -> 'Pod':
        """Represents the definition of a pod spec in legacy Kubernetes models.

        Use :meth:`Pod.set_spec` to set the container specification for legacy
        Kubernetes charms.

        .. deprecated:: 2.4.0
            New charms should use the sidecar pattern with Pebble.
        """
        return self._pod

    @property
    def name(self) -> str:
        """Return the name of the Model that this unit is running in.

        This is read from the environment variable ``JUJU_MODEL_NAME``.
        """
        return self._backend.model_name

    @property
    def uuid(self) -> str:
        """Return the identifier of the Model that this unit is running in.

        This is read from the environment variable ``JUJU_MODEL_UUID``.
        """
        return self._backend.model_uuid

    def get_unit(self, unit_name: str) -> 'Unit':
        """Get an arbitrary unit by name.

        Use :attr:`unit` to get the current unit.

        Internally this uses a cache, so asking for the same unit two times will
        return the same object.
        """
        return self._cache.get(Unit, unit_name)

    def get_app(self, app_name: str) -> 'Application':
        """Get an application by name.

        Use :attr:`app` to get this charm's application.

        Internally this uses a cache, so asking for the same application two times will
        return the same object.
        """
        return self._cache.get(Application, app_name)

    def get_relation(
        self, relation_name: str, relation_id: Optional[int] = None
    ) -> Optional['Relation']:
        """Get a specific Relation instance.

        If relation_id is not given, this will return the Relation instance if the
        relation is established only once or None if it is not established. If this
        same relation is established multiple times the error TooManyRelatedAppsError is raised.

        Args:
            relation_name: The name of the endpoint for this charm
            relation_id: An identifier for a specific relation. Used to disambiguate when a
                given application has more than one relation on a given endpoint.

        Raises:
            TooManyRelatedAppsError: is raised if there is more than one integration with the
                supplied relation_name and no relation_id was supplied
        """
        return self.relations._get_unique(relation_name, relation_id)

    def get_binding(self, binding_key: Union[str, 'Relation']) -> Optional['Binding']:
        """Get a network space binding.

        Args:
            binding_key: The relation name or instance to obtain bindings for.

        Returns:
            If ``binding_key`` is a relation name, the method returns the default binding
            for that relation. If a relation instance is provided, the method first looks
            up a more specific binding for that specific relation ID, and if none is found
            falls back to the default binding for the relation name.
        """
        return self._bindings.get(binding_key)

    def get_secret(self, *, id: Optional[str] = None, label: Optional[str] = None) -> 'Secret':
        """Get the :class:`Secret` with the given ID or label.

        The caller must provide at least one of `id` (the secret's locator ID)
        or `label` (the charm-local "name").

        If both are provided, the secret will be fetched by ID, and the
        secret's label will be updated to the label provided. Normally secret
```python
    # Copyright (c) ONNX Project Contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Implements function make_large_model to easily create and save models
bigger than 2 Gb.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from typing import Any, Iterable

import numpy as np

import onnx
import onnx.external_data_helper as ext_data
import onnx.helper
import onnx.onnx_cpp2py_export.checker as c_checker


def _set_external_data(
    tensor: onnx.TensorProto,
    location: str,
    offset: int | None = None,
    length: int | None = None,
    checksum: str | None = None,
    basepath: str | None = None,
) -> None:
    del tensor.external_data[:]
    tensor.data_location = onnx.TensorProto.EXTERNAL
    for k, v in {
        "location": location,
        "offset": offset,
        "length": length,
        "checksum": checksum,
        "basepath": basepath,
    }.items():
        if v is not None:
            entry = tensor.external_data.add()
            entry.key = k
            entry.value = str(v)


def _enumerate_subgraphs(graph):
    for node in graph.node:
        for att in node.attribute:
            if att.g:
                yield att.g
                yield from _enumerate_subgraphs(att.g)


def make_large_tensor_proto(
    location: str, tensor_name: str, tensor_type: int, shape: tuple[int, ...]
) -> onnx.TensorProto:
    """Create an external tensor.

    Arguments:
        location: unique identifier (not necessary a path)
        tensor_name: tensor name in the graph
        tensor_type: onnx type
        shape: shape the of the initializer

    Returns:
        the created tensor
    """
    tensor_location = location
    tensor = onnx.TensorProto()
    tensor.name = tensor_name
    _set_external_data(tensor, tensor_location)
    tensor.data_type = tensor_type
    tensor.dims.extend(shape)
    return tensor


class ModelContainer:
    """Implements an API to store large tensors outside the main ModelProto,
    it avoids copying large initializers when defining the model and these initializers
    are never serialized through protobuf.
    No tensor is stored on disk until the user explicitly saves the model.
    """

    def __init__(self):
        self.model_proto_: onnx.ModelProto | None = None
        self.large_initializers: dict[str, np.ndarray] = {}

    def check_model(self):
        if self.model_proto is not None:
            onnx.checker.check_model(self.model_proto)

    def __getitem__(self, name: str) -> np.ndarray:
        """Returns an external tensor given its name."""
        if name not in self.large_initializers:
            raise ValueError(
                f"Unable to find large tensor {name!r} among {sorted(self.large_initializers)}."
            )
        return self.large_initializers[name]

    @property
    def model_proto(self) -> onnx.ModelProto:
        if self.model_proto_ is None:
            raise RuntimeError("ModelContainer is empty.")
        return self.model_proto_

    @model_proto.setter
    def model_proto(self, model_proto: onnx.ModelProto):
        self.model_proto_ = model_proto
        self.graphs_ = list(self.enumerate_graph_protos())

    def enumerate_graph_protos(self) -> Iterable[onnx.GraphProto]:
        """Enumerates all GraphProtos in a model."""
        yield self.model_proto.graph
        yield from _enumerate_subgraphs(self.model_proto.graph)

    def is_in_memory_external_initializer(self, name: str) -> bool:
        """Tells if an initializer name is an external initializer stored in memory.
        The name must start with '#' in that case.
        """
        return name.startswith("#")

    def set_large_initializers(self, large_initializers: dict[str, np.ndarray]):
        """Adds all large tensors (not stored in the model)."""
        for k in large_initializers:
            if not self.is_in_memory_external_initializer(k):
                raise ValueError(
                    f"The location {k!r} must start with '#' to be ignored by check model."
                )
        self.large_initializers = large_initializers

    def check_large_initializers(self):
        for tensor in ext_data._get_all_tensors(self.model_proto):
            if not ext_data.uses_external_data(tensor):
                continue
            prop: onnx.StringStringEntryProto | None = None
            for ext in tensor.external_data:  # type: ignore[assignment]
                if ext.key == "location":  # type: ignore[attr-defined]
                    prop = ext
            if prop is None:
                raise RuntimeError(
                    f"No location found for tensor name {tensor.name!r}."
                )
            if prop.value not in self.large_initializers:
                raise RuntimeError(
                    f"Unable to find large tensor named {tensor.name!r} "
                    f"with location {prop.value!r} in "
                    f"{sorted(self.large_initializers)}."
                )

    def _save_external(
        self, file_path: str, all_tensors_to_one_file: bool
    ) -> onnx.ModelProto:
        """Save the large model into a main onnx file and one file
        per tensor. Follows the same format as :func:`write_external_data_tensors
        <onnx.external_data_helper.write_external_data_tensors>`.
        The main model needs to be modified to update the file location,
        the function returns this modified copy.

        Arguments:
            file_path: model file
            all_tensors_to_one_file: all tensors in one file

        Returns:
            modified main model proto
        """

        def _clean_name(prefix: str, name: str, unique_names: dict[str, int]) -> str:
            if prefix:
                name = f"{prefix}-{name}"
            for c in ":/\\;,!":
                name = name.replace(c, "")
            base_name = name
            if name in unique_names:
                i = unique_names[name] + 1
                unique_names[name] = i
                return f"{base_name}_{i}"
            unique_names[name] = 1
            return name

        unique_names: dict[str, int] = {}
        folder = os.path.dirname(file_path)
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        proto = self.model_proto.SerializeToString()
        copy = onnx.ModelProto()
        copy.ParseFromString(proto)
        prefix = os.path.splitext(os.path.split(file_path)[-1])[0]

        if all_tensors_to_one_file:
            file_weight = f"{os.path.split(file_path)[1]}.weight"
            full_file_weight = f"{file_path}.weight"
            offset = 0
            with tempfile.NamedTemporaryFile(dir=folder) as f:
                pass
            with open(full_file_weight, "wb") as f:
                pass

        for tensor in ext_data._get_all_tensors(copy):
            if not ext_data.uses_external_data(tensor):
                continue
            prop: onnx.StringStringEntryProto | None = None
            for ext in tensor.external_data:  # type: ignore[assignment]
                if ext.key == "location":  # type: ignore[attr-defined]
                    prop = ext  # type: ignore[assignment]
            if prop is None:
                raise RuntimeError(
                    f"No location found for tensor name {tensor.name!r}."
                )
            if prop.value not in self.large_initializers:
                raise RuntimeError(
                    f"Unable to find large tensor named {tensor.name!r} "
                    f"with location {prop.value!r} in "
                    f"{sorted(self.large_initializers)}."
                )
            np_tensor = self.large_initializers[
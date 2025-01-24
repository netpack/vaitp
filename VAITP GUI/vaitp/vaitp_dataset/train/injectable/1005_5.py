

def set_storage_slots_with_overrides(
    vyper_module: vy_ast.Module, storage_layout_overrides: StorageLayout
) -> StorageLayout:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    Returns the layout as a dict of variable name -> variable info
    """

    ret: Dict[str, Dict] = {}
    reserved_slots = StorageAllocator()

    # Search through function definitions to find non-reentrant functions
    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]

        # Ignore functions without nonreentrant
        if type_.nonreentrant is None:
            continue

        variable_name = f"nonreentrant.{type_.nonreentrant}"

        # re-entrant key was already identified
        if variable_name in ret:
            _slot = ret[variable_name]["slot"]
            type_.set_reentrancy_key_position(StorageSlot(_slot))
            continue

        # Expect to find this variable within the storage layout override
        if variable_name in storage_layout_overrides:
            layout = storage_layout_overrides[variable_name]
            if not isinstance(layout, dict) or "slot" not in layout:
                 raise StorageLayoutException(
                    f"Invalid storage layout override for {variable_name}. "
                    "Expected a dictionary with a 'slot' key.",
                    node,
                )
            reentrant_slot = layout["slot"]
            if not isinstance(reentrant_slot, int):
                 raise StorageLayoutException(
                    f"Invalid storage slot for {variable_name}. "
                    "Expected an int.",
                    node,
                )
            # Ensure that this slot has not been used, and prevents other storage variables
            # from using the same slot
            reserved_slots.reserve_slot_range(reentrant_slot, 1, variable_name)

            type_.set_reentrancy_key_position(StorageSlot(reentrant_slot))

            ret[variable_name] = {"type": "nonreentrant lock", "slot": reentrant_slot}
        else:
            raise StorageLayoutException(
                f"Could not find storage_slot for {variable_name}. "
                "Have you used the correct storage layout file?",
                node,
            )

    # Iterate through variables
    for node in vyper_module.get_children(vy_ast.VariableDecl):
        # Ignore immutable parameters
        if node.get("annotation.func.id") == "immutable":
            continue

        varinfo = node.target._metadata["varinfo"]

        # Expect to find this variable within the storage layout overrides
        if node.target.id in storage_layout_overrides:
            layout = storage_layout_overrides[node.target.id]
            if not isinstance(layout, dict) or "slot" not in layout:
                 raise StorageLayoutException(
                    f"Invalid storage layout override for {node.target.id}. "
                    "Expected a dictionary with a 'slot' key.",
                    node,
                )
            var_slot = layout["slot"]
            if not isinstance(var_slot, int):
                 raise StorageLayoutException(
                    f"Invalid storage slot for {node.target.id}. "
                    "Expected an int.",
                    node,
                )
            if var_slot < 0 or var_slot >= 2**256:
                raise StorageLayoutException(
                    f"Storageslot for {node.target.id} out of bounds: {var_slot}.",
                    node,
                )
            storage_length = varinfo.typ.storage_size_in_words
            # Ensure that all required storage slots are reserved, and prevents other variables
            # from using these slots
            try:
                reserved_slots.reserve_slot_range(var_slot, storage_length, node.target.id)
            except StorageLayoutException as e:
                e.node = node
                raise e
            varinfo.set_position(StorageSlot(var_slot))

            ret[node.target.id] = {"type": str(varinfo.typ), "slot": var_slot}
        else:
            raise StorageLayoutException(
                f"Could not find storage_slot for {node.target.id}. "
                "Have you used the correct storage layout file?",
                node,
            )

    return ret


def set_storage_slots(vyper_module: vy_ast.Module) -> StorageLayout:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    Returns the layout as a dict of variable name -> variable info
    """

    # Allocate storage slots from 0
    # note storage is word-addressable, not byte-addressable
    allocator = SimpleStorageAllocator()

    ret: Dict[str, Dict] = {}

    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]
        if type_.nonreentrant is None:
            continue

        variable_name = f"nonreentrant.{type_.nonreentrant}"

        # a nonreentrant key can appear many times in a module but it
        # only takes one slot. after the first time we see it, do not
        # increment the storage slot.
        if variable_name in ret:
            _slot = ret[variable_name]["slot"]
            type_.set_reentrancy_key_position(StorageSlot(_slot))
            continue

        # TODO use one byte - or bit - per reentrancy key
        # requires either an extra SLOAD or caching the value of the
        # location in memory at entrance
        slot = allocator.allocate_slot(1, variable_name)

        type_.set_reentrancy_key_position(StorageSlot(slot))

        # TODO this could have better typing but leave it untyped until
        # we nail down the format better
        ret[variable_name] = {"type": "nonreentrant lock", "slot": slot}


    for node in vyper_module.get_children(vy_ast.VariableDecl):
        # skip non-storage variables
        if node.is_constant or node.is_immutable:
            continue

        varinfo = node.target._metadata["varinfo"]
        type_ = varinfo.typ

        # CMC 2021-07-23 note that HashMaps get assigned a slot here.
        # I'm not sure if it's safe to avoid allocating that slot
        # for HashMaps because downstream code might use the slot
        # ID as a salt.
        n_slots = type_.storage_size_in_words
        try:
            slot = allocator.allocate_slot(n_slots, node.target.id)
        except StorageLayoutException as e:
            e.node = node
            raise e

        varinfo.set_position(StorageSlot(slot))

        # this could have better typing but leave it untyped until
        # we understand the use case better
        ret[node.target.id] = {"type": str(type_), "slot": slot}

    return ret
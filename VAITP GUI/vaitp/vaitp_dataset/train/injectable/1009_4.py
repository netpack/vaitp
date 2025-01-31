# a contract.vy -- all functions and constructor

from typing import Any, Dict, List, Optional, Tuple

from vyper import ast as vy_ast
from vyper.ast.signatures.function_signature import FunctionSignature, FunctionSignatures
from vyper.codegen.core import shr
from vyper.codegen.function_definitions import generate_ir_for_function
from vyper.codegen.global_context import GlobalContext
from vyper.codegen.ir_node import IRnode
from vyper.exceptions import CompilerPanic
from vyper.semantics.types.function import StateMutability


def _topsort_helper(functions, lookup):
    #  single pass to get a global topological sort of functions (so that each
    # function comes after each of its callees). may have duplicates, which get
    # filtered out in _topsort()

    ret = []
    for f in functions:
        # called_functions is a list of ContractFunctions, need to map
        # back to FunctionDefs.
        callees = [lookup[t.name] for t in f._metadata.get("type", {}).get("called_functions", []) if t.name in lookup]
        ret.extend(_topsort_helper(callees, lookup))
        ret.append(f)

    return ret


def _topsort(functions):
    lookup = {f.name: f for f in functions}
    # strip duplicates
    return list(dict.fromkeys(_topsort_helper(functions, lookup)))


def _is_init_func(func_ast):
    return func_ast._metadata.get("signature", {}).is_init_func


def _is_default_func(func_ast):
    return func_ast._metadata.get("signature", {}).is_default_func


def _is_internal(func_ast):
    return func_ast._metadata.get("type", {}).is_internal


def _is_payable(func_ast):
    return func_ast._metadata.get("type", {}).mutability == StateMutability.PAYABLE


# codegen for all runtime functions + callvalue/calldata checks + method selector routines
def _runtime_ir(runtime_functions, all_sigs, global_ctx):
    # categorize the runtime functions because we will organize the runtime
    # code into the following sections:
    # payable functions, nonpayable functions, fallback function, internal_functions
    internal_functions = [f for f in runtime_functions if _is_internal(f)]

    external_functions = [f for f in runtime_functions if not _is_internal(f)]
    default_function = next((f for f in external_functions if _is_default_func(f)), None)

    # functions that need to go exposed in the selector section
    regular_functions = [f for f in external_functions if not _is_default_func(f)]
    payables = [f for f in regular_functions if _is_payable(f)]
    nonpayables = [f for f in regular_functions if not _is_payable(f)]

    # create a map of the IR functions since they might live in both
    # runtime and deploy code (if init function calls them)
    internal_functions_map: Dict[str, IRnode] = {}

    for func_ast in internal_functions:
        func_ir = generate_ir_for_function(func_ast, all_sigs, global_ctx, False)
        internal_functions_map[func_ast.name] = func_ir

    # for some reason, somebody may want to deploy a contract with no
    # external functions, or more likely, a "pure data" contract which
    # contains immutables
    if not external_functions:
        # TODO: prune internal functions in this case?
        runtime = ["seq"] + list(internal_functions_map.values())
        return runtime, internal_functions_map

    # note: if the user does not provide one, the default fallback function
    # reverts anyway. so it does not hurt to batch the payable check.
    default_is_nonpayable = default_function is None or not _is_payable(default_function)

    # when a contract has a nonpayable default function,
    # we can do a single check for all nonpayable functions
    batch_payable_check = len(nonpayables) > 0 and default_is_nonpayable
    skip_nonpayable_check = batch_payable_check

    selector_section = ["seq"]

    for func_ast in payables:
        func_ir = generate_ir_for_function(func_ast, all_sigs, global_ctx, False)
        selector_section.append(func_ir)

    if batch_payable_check:
        selector_section.append(["assert", ["iszero", "callvalue"]])

    for func_ast in nonpayables:
        func_ir = generate_ir_for_function(func_ast, all_sigs, global_ctx, skip_nonpayable_check)
        selector_section.append(func_ir)

    if default_function:
        fallback_ir = generate_ir_for_function(
            default_function, all_sigs, global_ctx, skip_nonpayable_check
        )
    else:
        fallback_ir = IRnode.from_list(
            ["revert", 0, 0], annotation="Default function", error_msg="fallback function"
        )

    # ensure the external jumptable section gets closed out
    # (for basic block hygiene and also for zksync interpreter)
    # NOTE: this jump gets optimized out in assembly since the
    # fallback label is the immediate next instruction,
    close_selector_section = ["goto", "fallback"]

    runtime = [
        "seq",
        ["with", "_calldata_method_id", shr(224, ["calldataload", 0]), selector_section],
        close_selector_section,
        ["label", "fallback", ["var_list"], fallback_ir],
    ]

    # TODO: prune unreachable functions?
    runtime.extend(internal_functions_map.values())

    return runtime, internal_functions_map


# take a GlobalContext, which is basically
# and generate the runtime and deploy IR, also return the dict of all signatures
def generate_ir_for_module(global_ctx: GlobalContext) -> Tuple[IRnode, IRnode, FunctionSignatures]:
    # order functions so that each function comes after all of its callees
    function_defs = _topsort(global_ctx.functions)

    # FunctionSignatures for all interfaces defined in this module
    all_sigs: Dict[str, FunctionSignatures] = {}

    init_function: Optional[vy_ast.FunctionDef] = None
    local_sigs: FunctionSignatures = {}  # internal/local functions

    # generate all signatures
    # TODO really this should live in GlobalContext
    for f in function_defs:
        sig = FunctionSignature.from_definition(f, global_ctx)
        # add it to the global namespace.
        local_sigs[sig.name] = sig
        # a little hacky, eventually FunctionSignature should be
        # merged with ContractFunction and we can remove this.
        f._metadata["signature"] = sig

    assert "self" not in all_sigs
    all_sigs["self"] = local_sigs

    runtime_functions = [f for f in function_defs if not _is_init_func(f)]
    init_function = next((f for f in function_defs if _is_init_func(f)), None)

    runtime, internal_functions = _runtime_ir(runtime_functions, all_sigs, global_ctx)

    deploy_code: List[Any] = ["seq"]
    immutables_len = global_ctx.immutable_section_bytes
    if init_function:
        init_func_ir = generate_ir_for_function(init_function, all_sigs, global_ctx, False)
        deploy_code.append(init_func_ir)

        # pass the amount of memory allocated for the init function
        # so that deployment does not clobber while preparing immutables
        # note: (deploy mem_ofst, code, extra_padding)
        init_mem_used = init_function._metadata.get("signature", {}).frame_info.mem_used
        deploy_code.append(["deploy", init_mem_used, runtime, immutables_len])

        # internal functions come after everything else
        for f in init_function._metadata.get("type", {}).get("called_functions",[]):
            if f.name in internal_functions:
                deploy_code.append(internal_functions[f.name])

    else:
        if immutables_len != 0:
            raise CompilerPanic("unreachable")
        deploy_code.append(["deploy", 0, runtime, 0])

    return IRnode.from_list(deploy_code), IRnode.from_list(runtime), local_sigs
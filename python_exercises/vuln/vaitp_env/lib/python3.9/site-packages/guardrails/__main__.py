"""Koninklijke Philips N.V., 2019 - 2020. All rights reserved."""

import sys
from guardrails.guardrails import Guardails
from guardrails.guardrails import create_parser

if __name__ == '__main__':
    ARGS = create_parser(sys.argv[1:])
    GUARD_OBJ = Guardails(ARGS.path)
    GUARD_OBJ.orchestrate_guardrails()


import types

def load(doc):
    code = config.retrieveBoilerplateFile(doc, "bs-extensions", allowLocal=False)
    try:
        compiled_code = compile(code, '<string>', 'exec')
        module = types.ModuleType('bs_extensions')
        exec(compiled_code, module.__dict__)
        globals().update({k: v for k, v in module.__dict__.items() if not k.startswith('_')})
    except Exception as e:
        # Log the exception or handle it as needed
        pass
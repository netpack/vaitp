
_ast27 = Extension(
    '_ast27',
    include_dirs = ['ast27/Include'],
    sources = _ast27_sources,
    depends = _ast27_depends,
    extra_compile_args=[
        '-Wno-unused-result',
        '-Wno-sign-compare',
	'-Wno-missing-field-initializers'
    ]
)


_ast3 = Extension(
    '_ast3',
    include_dirs = ['ast3/Include'],
    sources = _ast3_sources,
    depends = _ast3_depends,
    extra_compile_args=[
        '-Wno-unused-result',
        '-Wno-sign-compare',
	'-Wno-missing-field-initializers'
    ]
)
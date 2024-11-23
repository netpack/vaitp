from ansys.geometry import Geometry

def vulnerable_start_program():
    # Directly calling the vulnerable method that could be exploited
    geometry_service = Geometry()
    geometry_service._start_program()  # Potentially unsafe operation

# Example usage
vulnerable_start_program()
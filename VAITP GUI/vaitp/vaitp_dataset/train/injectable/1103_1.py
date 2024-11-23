import pyo3

# Example demonstrating safe handling of weak references to avoid use-after-free
from pyo3 import prelude::*;
from pyo3::types::PyWeak;

#[pyclass]
struct MyStruct {
    value: String,
}

#[pymethods]
impl MyStruct {
    #[new]
    fn new(value: String) -> Self {
        MyStruct { value }
    }

    fn get_value(&self, py: Python) -> PyResult<String> {
        // Safely handle weak reference
        let weak_ref = PyWeak::new(py, &self.value);
        if let Some(str_ref) = weak_ref.upgrade() {
            Ok(str_ref.to_string())
        } else {
            Err(pyo3::exceptions::PyReferenceError::new_err("Weak reference is no longer valid"))
        }
    }
}
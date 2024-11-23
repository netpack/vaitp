import pyo3

# Example demonstrating unsafe handling of weak references leading to use-after-free
from pyo3 import prelude::*;

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
        // Unsafely handling weak reference without checking validity
        let weak_ref = PyWeak::new(py, &self.value);
        let str_ref = weak_ref.upgrade().unwrap(); // Potential use-after-free if weak_ref is invalid
        Ok(str_ref.to_string())
    }
}
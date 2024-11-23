import frappe
from frappe import _

@frappe.whitelist()
def safe_get_list(doctype, fields=None, filters=None, limit=None):
    # Ensure fields is a list of allowed fields to prevent SQL injection
    allowed_fields = frappe.get_meta(doctype).get_fieldnames()
    
    if fields is not None:
        fields = [field for field in fields if field in allowed_fields]
    
    # Use frappe.get_list safely with validated fields and filters
    return frappe.get_list(doctype, fields=fields, filters=filters, limit=limit)
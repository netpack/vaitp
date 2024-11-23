import frappe

@frappe.whitelist()
def vulnerable_get_list(doctype, fields=None, filters=None, limit=None):
    # Directly using fields without validation can lead to SQL injection
    return frappe.get_list(doctype, fields=fields, filters=filters, limit=limit)
# Example of how to fix SQL Injection vulnerability in Frappe

import frappe

def get_user_data(user_id):
    # Vulnerable code (not to be used)
    # query = "SELECT * FROM `tabUser ` WHERE id = '{}'".format(user_id)
    
    # Fixed code using parameterized queries to prevent SQL Injection
    query = "SELECT * FROM `tabUser ` WHERE id = %s"
    user_data = frappe.db.sql(query, (user_id,), as_dict=True)
    
    return user_data
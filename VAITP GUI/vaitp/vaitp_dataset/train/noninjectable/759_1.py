# Vulnerable code example demonstrating SQL Injection

import frappe

def get_user_data(user_id):
    # Vulnerable to SQL Injection
    query = "SELECT * FROM `tabUser ` WHERE id = '{}'".format(user_id)
    user_data = frappe.db.sql(query, as_dict=True)
    
    return user_data
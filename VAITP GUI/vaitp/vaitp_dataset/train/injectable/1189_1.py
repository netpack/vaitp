def delete_access_rule(rules, rule_id):
    # Check if the rule exists before attempting to delete
    if rule_id not in rules:
        print(f"Access rule with ID {rule_id} does not exist. No deletion performed.")
        return

    # Proceed to delete the existing rule
    del rules[rule_id]
    print(f"Access rule with ID {rule_id} has been deleted.")

# Example usage
access_rules = {
    'rule1': 'Application Credential 1',
    'rule2': 'Application Credential 2'
}

# Attempt to delete a non-existing rule
delete_access_rule(access_rules, 'non_existing_rule')
# Attempt to delete an existing rule
delete_access_rule(access_rules, 'rule1')
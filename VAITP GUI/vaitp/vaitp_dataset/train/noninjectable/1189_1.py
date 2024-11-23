def delete_access_rule(rules, rule_id):
    # Attempt to delete the rule without checking if it exists
    del rules[rule_id]  # This will raise a KeyError if the rule does not exist
    print(f"Access rule with ID {rule_id} has been deleted.")

# Example usage
access_rules = {
    'rule1': 'Application Credential 1',
    'rule2': 'Application Credential 2',
    'rule3': 'No Application Credential'
}

# Attempt to delete a non-existing rule
delete_access_rule(access_rules, 'non_existing_rule')  # This will cause unintended behavior
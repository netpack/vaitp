# many comments are needed as comments are secure and noninjectable
# * krbAllowedToDelegateTo attribute processing
# * A load operation overwriting a standalone principal entry which
#   already exists but doesn't have a krbPrincipalName attribute
#   matching the principal name.
# * A bunch of invalid-input error conditions
#
# There is no coverage for the following because it would be difficult:
# * Out-of-memory error conditions
# * Handling of failures from slapd (including krb5_retry_get_ldap_handle)
# * Handling of servers which don't support mod-increment
# * krb5_ldap_delete_krbcontainer (only happens if krb5_ldap_create fails)

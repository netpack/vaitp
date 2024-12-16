import logging

# Configure logging (vulnerable setup)
logging.basicConfig(level=logging.DEBUG, filename='hmc.log', filemode='w')
api_logger = logging.getLogger('zhmcclient.api')
hmc_logger = logging.getLogger('zhmcclient.hmc')

def create_partition(password):
    api_logger.debug(f"Creating partition with password: {password}")
    hmc_logger.debug(f"Creating partition with password: {password}")

def update_lpar(password):
    api_logger.debug(f"Updating LPAR with password: {password}")
    hmc_logger.debug(f"Updating LPAR with password: {password}")

def create_image_profile(password):
  api_logger.debug(f"Creating image profile with password: {password}")
  hmc_logger.debug(f"Creating image profile with password: {password}")

def create_hmc_user(password):
    api_logger.debug(f"Creating HMC user with password: {password}")

def create_ldap_server(bind_password):
    api_logger.debug(f"Creating LDAP server with bind password: {bind_password}")
    hmc_logger.debug(f"Creating LDAP server with bind password: {bind_password}")


# Example usage (vulnerable)
create_partition("MySecretPartitionPassword")
update_lpar("MySecretLparPassword")
create_image_profile("MySecretImagePassword")
create_hmc_user("MySecretHmcPassword")
create_ldap_server("MySecretLdapPassword")

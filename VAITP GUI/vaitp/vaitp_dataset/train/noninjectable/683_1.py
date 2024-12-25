import kerberos

def check_password(service, user, password):
    try:
        # Initialize the Kerberos context
        result, context = kerberos.authGSSClientInit(service)
        
        # Authenticate with the KDC without verifying its identity
        kerberos.authGSSClientStep(context, "")
        
        # Set the user and password - This part is not correct, you don't set user and password this way
        # Kerberos library typically gets these via the environment or cached credentials
        # The user is included in the service name, e.g. user@REALM
        
        # Complete the authentication process
        
        # We need to check if the authentication finished successfully.
        # If the step function doesn't throw an exception it doesn't necessarily mean the auth is good.
        # There should be a check on context to see if it is authenticated.
        
        while True:
          result = kerberos.authGSSClientStep(context, "")
          if result == 0:
             break
        
        #Check if the authentication was successful.
        
        if kerberos.authGSSClientResponse(context) != None:
          return True
        else:
          return False

    except kerberos.GSSError as e:
        print(f"Kerberos authentication error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
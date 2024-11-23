import kerberos

def check_password(service, user, password):
    try:
        # Initialize the Kerberos context
        result, context = kerberos.authGSSClientInit(service)
        
        # Authenticate with the KDC without verifying its identity
        kerberos.authGSSClientStep(context, "")
        
        # Set the user and password
        kerberos.authGSSClientUser Name(context, user)
        kerberos.authGSSClientPassword(context, password)

        # Complete the authentication process
        kerberos.authGSSClientStep(context, "")
        
        return True
    except kerberos.GSSError as e:
        print(f"Kerberos authentication error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
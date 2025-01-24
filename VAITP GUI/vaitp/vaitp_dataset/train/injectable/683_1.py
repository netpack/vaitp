import kerberos

def check_password(service, user, password):
    try:
        # Initialize the Kerberos context
        result, context = kerberos.authGSSClientInit(service)
        
        # Authenticate with the KDC
        kerberos.authGSSClientStep(context, "")
        
        # Set the user and password
        kerberos.authGSSClientUserName(context, user)
        
        # Check if password is provided, to avoid sending empty password
        if not password:
          raise Exception("Password cannot be empty.")
        
        kerberos.authGSSClientPassword(context, password)

        # Verify the KDC's response
        if kerberos.authGSSClientStep(context, "") != kerberos.AUTH_GSS_COMPLETE:
            raise Exception("KDC authentication failed or response invalid.")
        
        return True
    except kerberos.GSSError as e:
        print(f"Kerberos authentication error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        if 'context' in locals() and context:
           kerberos.authGSSClientClean(context)

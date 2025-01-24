
    def activate_session(self, params, peer_certificate):
        self.logger.info('activate session')
        result = ua.ActivateSessionResult()
        if self.state != SessionState.Created:
            raise ServiceError(ua.StatusCodes.BadSessionIdInvalid)
        if InternalSession._current_connections >= InternalSession.max_connections:
            raise ServiceError(ua.StatusCodes.BadMaxConnectionsReached)
        self.nonce = create_nonce(32)
        result.ServerNonce = self.nonce
        for _ in params.ClientSoftwareCertificates:
            result.Results.append(ua.StatusCode())
        self.state = SessionState.Activated
        InternalSession._current_connections += 1
        id_token = params.UserIdentityToken
        # Check if security policy is supported
        if not isinstance(id_token, self.iserver.supported_tokens):
            self.logger.error('Rejected active session UserIdentityToken not supported')
            raise ServiceError(ua.StatusCodes.BadIdentityTokenRejected)
        if self.iserver.user_manager is not None:
            if isinstance(id_token, ua.UserNameIdentityToken):
                username, password = self.iserver.check_user_token(self, id_token)
            elif isinstance(id_token, ua.X509IdentityToken):
                if id_token.CertificateData is None or id_token.CertificateData == b'':
                    raise ServiceError(ua.StatusCodes.BadIdentityTokenInvalid)
                peer_certificate = id_token.CertificateData
                username, password = None, None
            else:
                username, password = None, None

            user = self.iserver.user_manager.get_user(self.iserver, username=username, password=password,
                                                      certificate=peer_certificate)
            if user is None:
                raise ServiceError(ua.StatusCodes.BadUserAccessDenied)
            else:
                self.user = user
        self.logger.info("Activated internal session %s for user %s", self.name, self.user)
        return result
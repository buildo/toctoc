package io.buildo.toctoc.authentication

import slick.jdbc.JdbcBackend.Database

import io.buildo.toctoc.authentication.TokenBasedAuthentication.TokenBasedAuthenticationFlow
import io.buildo.toctoc.authentication.token.SlickAccessTokenAuthenticationDomain
import io.buildo.toctoc.authentication.login.SlickLoginAuthenticationDomain

import slick.jdbc.JdbcBackend.Database

class SlickTokenBasedAuthenticationFlow(tokenExpireTimeSeconds: Long, db: Database)
  extends TokenBasedAuthenticationFlow(
    loginD = new SlickLoginAuthenticationDomain(db),
    accessTokenD = new SlickAccessTokenAuthenticationDomain(db)
  )
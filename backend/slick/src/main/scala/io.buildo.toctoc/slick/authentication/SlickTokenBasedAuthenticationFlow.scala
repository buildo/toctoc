package io.buildo.toctoc
package slick
package authentication

import core.authentication.TokenBasedAuthentication.TokenBasedAuthenticationFlow
import token.SlickAccessTokenAuthenticationDomain
import login.SlickLoginAuthenticationDomain

import _root_.slick.jdbc.JdbcBackend.Database

import scala.concurrent.ExecutionContext

import java.time.Duration

class SlickTokenBasedAuthenticationFlow(
  db: Database,
  tokenDuration: Duration = Duration.ofDays(365)
)(implicit ec: ExecutionContext)
  extends TokenBasedAuthenticationFlow(
    loginD = new SlickLoginAuthenticationDomain(db),
    accessTokenD = new SlickAccessTokenAuthenticationDomain(db),
    tokenDuration = tokenDuration
  )
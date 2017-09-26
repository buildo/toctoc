# autho

## Authentication

### Login

```scala
trait SecretCredentials {
  def secret: String
}

case class AccessToken(value: String) extends AnyVal
case class RefreshToken(value: String) extends AnyVal

selaed abstract trait Token {
  def accessToken: AccessToken
  def refreshToken: RefreshToken
  def expiresAt: DateTime
}

case class ValidToken(
  accessToken: AccessToken,
  refreshToken: RefreshToken,
  expiresAt: DateTime
) extends Token

case class CredentialsExpiredToken(
  accessToken: AccessToken,
  refreshToken: RefreshToken,
  expiresAt: DateTime
) extends Token

abstract sealed trait CredentialsError
case class InvalidCredentials extends CredentialsError
case class DisabledCredentials extends CredentialsError

case class PasswordCredentials(
  username: String,
  password: String
) extends SecretCredentials {
  def secret = s"$username$password"
}

def exchangeCredentials(c: SecretCredentials): Future[Either[CredentialsError, Token]]

```
### Authenticate

```scala
abstract sealed trait AuthenticationError
case class InvalidAccessToken extends AuthenticationError
case class ExpiredAccessToken extends AuthenticationError

case class Subject[SubjectId] {
  // def id: java.util.UUID
  def ref: SubjectId
}

def authenticate(t: AccessToken): Either[AuthenticationError, Subject]

```

### Refresh

```scala
abstract sealed trait RefreshError
case class InvalidRefreshToken extends RefreshError

def refreshToken(t: RefreshToken): Either[RefreshError, Token]

```

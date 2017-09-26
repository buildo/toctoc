# autho

## Authentication

### Login 

```scala
trait SecretCredentials {
  def secret: String
}

case class PasswordCredentials(
 val username: String, 
 val password: String
) extends SecretCredentials {
  def secret = s"$username$password"
}

selaed abstract trait Token {
  def value: String
}
case class Token(
 value: String,
 expired: Boolean
)

def exchangeCredentials(c: SecretCredentials): Future[Either[CredentialsError, Token]]

abstract sealed trait CredentialsError
case class InvalidCredentials extends CredentialsError

```
### Authenticate 

```scala
def authenticate(t: Token): Either[Error, Subject]
```

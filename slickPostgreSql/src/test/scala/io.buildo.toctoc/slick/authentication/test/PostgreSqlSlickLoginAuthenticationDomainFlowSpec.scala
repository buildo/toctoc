package io.buildo.toctoc
package slick
package authentication
package test

import core.authentication.TokenBasedAuthentication._
import login.PostgreSqlSlickLoginAuthenticationDomain
import token.PostgreSqlSlickAccessTokenAuthenticationDomain

import org.scalatest._
import _root_.slick.jdbc.PostgresProfile.api._
import _root_.slick.jdbc.JdbcBackend.Database

import cats.effect.IO

class PostgreSqlSlickLoginAuthenticationDomainFlowSpec
    extends FlatSpec
    with BeforeAndAfterEach
    with BeforeAndAfterAll
    with EitherValues
    with Matchers {

  val db = Database.forConfig("db")
  val loginAuthDomain = new PostgreSqlSlickLoginAuthenticationDomain[IO](db)
  val accessTokenAuthDomain =
    new PostgreSqlSlickAccessTokenAuthenticationDomain[IO](db)

  val loginTable = loginAuthDomain.loginTable
  val accessTokenTable = accessTokenAuthDomain.accessTokenTable
  val schema = loginTable.schema ++ accessTokenTable.schema

  val authFlow = new PostgreSqlSlickTokenBasedAuthenticationFlow[IO](db)

  override def beforeAll() = {
    IO.fromFuture(IO(db.run(schema.create))).unsafeRunSync
  }

  override def afterEach() = {
    IO.fromFuture(IO(db.run(schema.truncate))).unsafeRunSync
  }

  override def afterAll() = {
    IO.fromFuture(IO(db.run(schema.drop))).unsafeRunSync
    db.close()
  }

  val login = Login("username", "password")
  val login2 = Login("usernameoso", "password")
  val login3 = Login("usernameosone", "password")
  val subject = UserSubject("test")
  val subject2 = UserSubject("test2")

  "unregistered login credentials" should "not be accepted when exchanging for token" in {
    authFlow.exchangeForTokens(login).unsafeRunSync shouldBe 'left
  }

  "registered login credentials" should "be accepted when exchanging for token" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.exchangeForTokens(login).unsafeRunSync shouldBe 'right
  }

  "token obtained by login" should "be validated" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    val token = authFlow.exchangeForTokens(login).unsafeRunSync.right.value
    authFlow.validateToken(token).unsafeRunSync.right.value shouldBe subject
  }

  "multiple login with same values" should "not be accepted in registration" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'left
  }

  "multiple login with different values" should "be accepted in registration" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.registerSubjectLogin(subject2, login2).unsafeRunSync shouldBe 'right
    val token2 = authFlow.exchangeForTokens(login2).unsafeRunSync.right.value
    authFlow.validateToken(token2).unsafeRunSync.right.value shouldBe subject2
  }

  "single token unregistration" should "unregister only the specific token" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.registerSubjectLogin(subject2, login2).unsafeRunSync shouldBe 'right
    val token = authFlow.exchangeForTokens(login).unsafeRunSync.right.value
    val token2 = authFlow.exchangeForTokens(login2).unsafeRunSync.right.value
    authFlow.unregisterToken(token).unsafeRunSync
    authFlow.validateToken(token).unsafeRunSync shouldBe 'left
    authFlow.validateToken(token2).unsafeRunSync shouldBe 'right
  }

  "token unregistration" should "unregister all subject's tokens" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.registerSubjectLogin(subject2, login2).unsafeRunSync shouldBe 'right
    val token = authFlow.exchangeForTokens(login).unsafeRunSync.right.value
    val token2 = authFlow.exchangeForTokens(login).unsafeRunSync.right.value
    val token3 = authFlow.exchangeForTokens(login2).unsafeRunSync.right.value
    authFlow.unregisterAllSubjectTokens(subject).unsafeRunSync
    authFlow.validateToken(token).unsafeRunSync shouldBe 'left
    authFlow.validateToken(token2).unsafeRunSync shouldBe 'left
    authFlow.validateToken(token3).unsafeRunSync shouldBe 'right
  }

  "single subject credentials unregistration" should "take effect" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.unregisterLogin(login).unsafeRunSync
    authFlow.exchangeForTokens(login).unsafeRunSync shouldBe 'left
  }

  "subject credentials unregistration" should "take effect" in {
    authFlow.registerSubjectLogin(subject, login).unsafeRunSync shouldBe 'right
    authFlow.registerSubjectLogin(subject, login3).unsafeRunSync shouldBe 'right
    authFlow.unregisterAllSubjectLogins(subject).unsafeRunSync
    authFlow.exchangeForTokens(login).unsafeRunSync shouldBe 'left
    authFlow.exchangeForTokens(login3).unsafeRunSync shouldBe 'left
  }

}

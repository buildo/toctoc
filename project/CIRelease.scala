package com.geirsson

import com.typesafe.sbt.GitPlugin
import com.typesafe.sbt.SbtPgp
import com.typesafe.sbt.SbtPgp.autoImport._
import java.nio.file.Files
import java.nio.file.Paths
import java.util.Base64
import sbt.Def
import sbt.Keys._
import sbt._
import sbt.plugins.JvmPlugin
import sbtdynver.DynVerPlugin
import sbtdynver.DynVerPlugin.autoImport._
import scala.sys.process._
import xerial.sbt.Sonatype
import xerial.sbt.Sonatype.autoImport._
import scala.util.Try

object CiReleasePlugin extends AutoPlugin {

  override def trigger = allRequirements
  override def requires =
    JvmPlugin && SbtPgp && DynVerPlugin && GitPlugin && Sonatype

  def tag: Option[String] = {
    val refPath = Paths.get(".git", "ref")
    Try(new String(Files.readAllBytes(refPath))).toOption.filter(_.startsWith("v"))
  }

  def setupGpg(): Unit = {
    val secret = sys.env("PGP_SECRET")
    (s"echo $secret" #| "gpg --import").!
  }

  override def buildSettings: Seq[Def.Setting[_]] = List(
    dynverSonatypeSnapshots := true,
    pgpPassphrase := sys.env.get("PGP_PASSPHRASE").map(_.toCharArray()),
  )

  override def globalSettings: Seq[Def.Setting[_]] = List(
    publishArtifact.in(Test) := false,
    publishMavenStyle := true,
    commands += Command.command("ci-release") { currentState =>
      println("Running ci-release.\n")
      setupGpg()
      tag match {
        case None =>
          if (isSnapshotVersion(currentState)) {
            println(s"No tag push, publishing SNAPSHOT")
            sys.env.getOrElse("CI_SNAPSHOT_RELEASE", "+publish") ::
              currentState
          } else {
            println(
              "Snapshot releases must have -SNAPSHOT version number, doing nothing",
            )
            currentState
          }

        case Some(tag) =>
          println("Tag push detected, publishing a stable release")
          sys.env.getOrElse("CI_RELEASE", "+publishSigned") ::
            sys.env.getOrElse("CI_SONATYPE_RELEASE", "sonatypeRelease") ::
            currentState
      }
    },
  )

  override def projectSettings: Seq[Def.Setting[_]] = List(
    publishConfiguration :=
      publishConfiguration.value.withOverwrite(true),
    publishLocalConfiguration :=
      publishLocalConfiguration.value.withOverwrite(true),
    publishTo := sonatypePublishTo.value,
  )

  def isSnapshotVersion(state: State): Boolean = {
    version.in(ThisBuild).get(Project.extract(state).structure.data) match {
      case Some(v) => v.endsWith("-SNAPSHOT")
      case None    => throw new NoSuchFieldError("version")
    }
  }

}

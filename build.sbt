ThisBuild / scalaVersion := "2.12.10"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / organization := "com.example"
ThisBuild / organizationName := "example"

lazy val root = (project in file("."))
  .settings(
      name := "mw",
      libraryDependencies ++= Seq(
          "org.bouncycastle" % "bcprov-jdk15on" % "1.64",
          "org.bouncycastle" % "bcpkix-jdk15on" % "1.64",
          "org.scalatest" %% "scalatest" % "3.0.8" % Test
      )
  )

// See https://www.scala-sbt.org/1.x/docs/Using-Sonatype.html for instructions on how to publish to Sonatype.

---
id: installation
title: Installation
---

`toctoc` is composed by multiple modules:

- `toctoc-core`: defines the basic abstractions
- `toctoc-slick-postgresql`: provides slick-specific implementations for
  Postgres databases
- `toctoc-slick-mysql`: provides slick-specific implementations for MySql
  databases

You can cherry-pick the modules according to the needs of your project. For
example:

```scala
val V = new {
  val toctoc = "@STABLE_VERSION@"
}

libraryDependencies ++= List(
  "io.buildo" %% "toctoc-core" % V.toctoc,
  "io.buildo" %% "toctoc-slick-postgresql" % V.toctoc
)
```

## Snapshot versions

We publish a snapshot version on every merge on master.

The latest snapshot version is `@VERSION@` and you can use it to try the latest
unreleased features. For example:

```scala
val V = new {
  val toctoc = "@VERSION@"
}

libraryDependencies ++= List(
  "io.buildo" %% "toctoc-core" % V.toctoc,
  "io.buildo" %% "toctoc-slick-postgresql" % V.toctoc
)
```

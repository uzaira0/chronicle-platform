pluginManagement {
    plugins {
        kotlin("jvm")                               version "2.4.10" apply false

        id("org.jetbrains.dokka")                       version "2.2.0" apply false
        id("com.github.spotbugs")                       version "6.5.5" apply false
        id("org.owasp.dependencycheck")                 version "13.0.0" apply false
        id("org.hidetake.swagger.generator")            version "2.19.2" apply false
        id("com.github.johnrengelman.shadow")           version "8.1.1" apply false
        id("org.jetbrains.kotlin.plugin.spring")        version "2.4.10" apply false
        id("com.github.jk1.dependency-license-report")  version "3.1.2" apply false

        id("idea")
        id("jacoco")
        id("checkstyle")
        id("maven-publish")
        id("signing")
    }
    repositories {
        maven(url = "https://plugins.gradle.org/m2/")
        mavenCentral()
        maven(url = "https://maven.pkg.github.com/uzaira0/chronicle")
    }
}

rootProject.name="chronicle"

include("chronicle-models")
include("chronicle-api")
include("chronicle-server")
//include("chronicle")
include("rhizome")
include("rhizome-client")

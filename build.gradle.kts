import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import org.owasp.dependencycheck.gradle.tasks.Analyze
import org.owasp.dependencycheck.gradle.tasks.ConfiguredTask

/*
 * Root build configuration for Chronicle monorepo
 * Applies OWASP Dependency-Check plugin for security vulnerability scanning
 */

buildscript {
    // Raise-only Guava pin (gradles/guava.gradle) on the root plugin classpath; the subprojects
    // block below adds it to every subproject's buildscript/plugin classpath.
    project.apply(from = "gradles/guava.gradle")
    dependencies.components.all(project.extra["guavaPinMetadataRule"] as groovy.lang.Closure<*>)
    repositories { mavenCentral() }
    dependencies {
        val securityClasspathFloors = listOf(
            "com.fasterxml.jackson.core:jackson-databind:2.22.3",
            "org.jsoup:jsoup:1.23.2",
        )
        securityClasspathFloors.forEach { classpath(it) }
    }
}

plugins {
    id("org.jetbrains.kotlin.jvm") apply false
    id("org.jetbrains.kotlin.plugin.spring") apply false
    id("com.github.spotbugs") apply false
    id("org.jetbrains.dokka") apply false
    id("com.github.jk1.dependency-license-report") apply false
    id("org.owasp.dependencycheck") version "13.0.0" apply false
    id("com.github.ben-manes.versions") version "0.52.0" apply false
}

val dependencyCheckAutoUpdate = providers.gradleProperty("dependencyCheckAutoUpdate")
    .map { it.toBoolean() }
    .orElse(true)
val dependencyCheckOffline = providers.gradleProperty("dependencyCheckOffline")
    .map { it.toBoolean() }
    .orElse(false)
val dependencyCheckNvdDelayMillis = providers.gradleProperty("dependencyCheckNvdDelayMillis")
    .map { it.toInt() }
    .orElse(1000)
val dependencyCheckNvdMaxRetryCount = providers.gradleProperty("dependencyCheckNvdMaxRetryCount")
    .map { it.toInt() }
    .orElse(10)
val dependencyCheckNvdResultsPerPage = providers.gradleProperty("dependencyCheckNvdResultsPerPage")
    .map { it.toInt() }
    .orElse(2000)
// Shared across checkouts so incremental NVD updates reuse one database (scripts/local-ci.sh exports it).
val dependencyCheckDataDir = providers.environmentVariable("CHRONICLE_DEPCHECK_DATA_DIR")
    .orElse("${System.getProperty("user.home")}/.cache/chronicle/dependency-check-data")

val guavaPinMetadataRule = extra["guavaPinMetadataRule"] as groovy.lang.Closure<*>
subprojects {
    buildscript.dependencies.components.all(guavaPinMetadataRule)
}

// Apply OWASP dependency check + ben-manes/versions audit to all subprojects
subprojects {
    apply(plugin = "org.owasp.dependencycheck")
    apply(plugin = "com.github.ben-manes.versions")

    // ODC 13 gives task data an explicit default that hides the extension convention.
    tasks.withType<ConfiguredTask>().configureEach {
        data.directory.set(dependencyCheckDataDir)
        doFirst {
            check(data.directory.get() == dependencyCheckDataDir.get()) {
                "Dependency-Check must use the configured shared data directory"
            }
        }
    }

    // Dependency-Check does not track the mutable advisory database as an input.
    tasks.withType<Analyze>().configureEach {
        outputs.upToDateWhen { false }
    }

    // The jdk8 relocation stub also depends on jdk7 at the same version, so this
    // single force aligns both with kotlin_version in gradles/chronicle.gradle.
    configurations.configureEach {
        resolutionStrategy.force(
            "org.jetbrains.kotlin:kotlin-stdlib-jdk8:2.4.10",
        )
    }

    configure<DependencyCheckExtension> {
        outputDirectory.set(layout.buildDirectory.dir("reports"))
        autoUpdate = dependencyCheckAutoUpdate.get()
        val offline = dependencyCheckOffline.get()
        failBuildOnCVSS = 7.0f
        formats = listOf("HTML", "JSON", "SARIF")
        suppressionFile = "${rootProject.projectDir}/config/dependency-check-suppression.xml"
        scanConfigurations = listOf("runtimeClasspath")

        withGroovyBuilder {
            "data" {
                setProperty("directory", dependencyCheckDataDir.get())
            }
            "analyzers" {
                setProperty("jarEnabled", true)
                setProperty("nodeEnabled", false)
                setProperty("nodeAuditEnabled", false)
                setProperty("assemblyEnabled", false)
                "kev" {
                    setProperty("enabled", !offline)
                }
                "nodeAudit" {
                    setProperty("enabled", false)
                }
                "nodePackage" {
                    setProperty("enabled", false)
                }
                "ossIndex" {
                    setProperty("enabled", false)
                }
                "retirejs" {
                    setProperty("enabled", false)
                    setProperty("forceupdate", false)
                }
            }
            "hostedSuppressions" {
                setProperty("enabled", !offline)
                setProperty("forceupdate", false)
            }
            "nvd" {
                setProperty("apiKey", System.getenv("NVD_API_KEY") ?: (findProperty("nvdApiKey") as String? ?: ""))
                // Inter-request delay (ms) for the NVD API. With a valid API key NVD allows
                // ~1 request / 0.6s; 1000ms stays safely under that. (3500ms was needlessly
                // conservative and made a cold full-feed pull take 4h+.)
                setProperty("delay", dependencyCheckNvdDelayMillis.get())
                setProperty("maxRetryCount", dependencyCheckNvdMaxRetryCount.get())
                setProperty("resultsPerPage", dependencyCheckNvdResultsPerPage.get())
            }
        }
    }
}

tasks.register("dependencyCheckUpdateShared") {
    group = "verification"
    description = "Warms the shared OWASP Dependency-Check NVD database once for all subprojects"
    dependsOn(":chronicle-api:dependencyCheckUpdate")
}

// Aggregate dependency check task for all subprojects
tasks.register("dependencyCheckAll") {
    group = "verification"
    description = "Runs OWASP dependency-check analysis on all subprojects"
    dependsOn(subprojects.map { "${it.path}:dependencyCheckAnalyze" })
}

// Configure output directory for aggregate reports
tasks.register<Copy>("aggregateSecurityReports") {
    group = "verification"
    description = "Collects dependency-check reports produced by the explicit scan task"
    // Report aggregation must never trigger a second analysis. CI runs dependencyCheckAll
    // through scripts/local-ci.sh with the intended fresh/cache-only policy, then invokes
    // this task under `if: always()` solely to gather whatever evidence that run produced.
    subprojects.forEach { child ->
        from(child.layout.buildDirectory.dir("reports")) {
            into(child.name)
        }
    }
    into(rootProject.layout.buildDirectory.dir("reports/security"))
    include("**/dependency-check-report.*")
}

// Fixtures for `semgrep --test --config cwe-comprehensive.yaml cwe-comprehensive.kt`.
class StackTraceFixtures {
    fun leak(failure: Exception, body: MutableMap<String, Any>) {
        // ruleid: chronicle-stacktrace-in-response
        body["trace"] = failure.getStackTrace()
    }

    fun sanitize(failure: Exception): IllegalStateException {
        val sanitized = IllegalStateException("failed")
        // ok: chronicle-stacktrace-in-response
        sanitized.setStackTrace(failure.getStackTrace())
        return sanitized
    }
}

class LogInjectionFixtures {
    fun log(logger: org.slf4j.Logger, userId: String) {
        // ruleid: chronicle-log-injection
        logger.info("selected by " + userId)
    }

    fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        // ok: chronicle-log-injection
        db.execSQL("UPDATE `userQueue` SET seq = 0 " + "WHERE `userQueue`.seq IS NULL")
    }
}

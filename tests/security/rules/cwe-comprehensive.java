// Fixtures for `semgrep --test --config cwe-comprehensive.yaml cwe-comprehensive.java`.
import java.sql.SQLException;
import java.util.Map;
import org.apache.logging.log4j.core.pattern.LogEventPatternConverter;

class HardcodedPasswordFixtures {
    // ruleid: chronicle-hardcoded-password-java
    String dbPassword = "hunter2";
    // ruleid: chronicle-hardcoded-password-java
    String adminPassword = "password123";
    // ruleid: chronicle-hardcoded-password-java
    String stripeApiKey = "sk_live_abc";
    // ruleid: chronicle-hardcoded-password-java
    String clientSecret = "secretpassword";

    // Values that only name the credential field are keys, not credentials.
    // ok: chronicle-hardcoded-password-java
    String passwordField = "password";
    // ok: chronicle-hardcoded-password-java
    String clientSecretKey = "clientSecret";
    // ok: chronicle-hardcoded-password-java
    String keystorePasswordProperty = "keymanager-password";
    // ok: chronicle-hardcoded-password-java
    String secretName = "base64EncodedSecret";
    // ok: chronicle-hardcoded-password-java
    String emptyPassword = "";
}

class StackTraceFixtures {
    String leak( Exception failure, Map<String, Object> body ) {
        // ruleid: chronicle-stacktrace-in-response
        body.put( "trace", failure.getStackTrace() );
        return body.toString();
    }

    SQLException sanitize( SQLException failure ) {
        SQLException sanitized = new SQLException( "database error", failure.getSQLState() );
        // ok: chronicle-stacktrace-in-response
        sanitized.setStackTrace( failure.getStackTrace() );
        return sanitized;
    }
}

final class LogOnlyConverterFixture extends LogEventPatternConverter {
    private LogOnlyConverterFixture() { super( "Fixture", "throwable" ); }

    void frames( Throwable failure, StringBuilder log ) {
        // ok: chronicle-stacktrace-in-response
        for ( StackTraceElement frame : failure.getStackTrace() ) {
            log.append( frame );
        }
    }
}

// Positive fixture for the collection-dto Semgrep rule.
//
// This DTO deliberately declares secret-bearing fields that the rule forbids
// in shared collection DTOs. `semgrep --test` confirms the rule fires on each
// annotated line. Not production code — never compiled, never scanned by the
// `collection` layer's real-code target.
package tests.security.fixtures.collection

data class BadDiagnosticsDto(
    val moduleId: String,
    // ruleid: chronicle-collection-dto-no-secret-fields
    val apiKey: String,
    // ruleid: chronicle-collection-dto-no-secret-fields
    val participantId: String,
    // ruleid: chronicle-collection-dto-no-secret-fields
    var signingSecret: String? = null,
)

#!/usr/bin/env python3
"""Require a caller or a documented external contract for every production route."""
import argparse
import json
import subprocess
from pathlib import Path
import re
import sys

# API-only controls require an explicit reason; an unknown operation fails closed.
API_ONLY = {
    "StudyLifecycleController.cloneStudy": "Study cloning is an API-only bulk setup operation.",
    "WebhookController.createWebhook": "Webhook registrations are disclosed and managed through the integration API.",
    "WebhookController.deleteWebhook": "Webhook registrations are managed through the integration API.",
    "WebhookController.testWebhook": "Webhook tests belong to the integration API.",
    "ApiKeyController.rotateApiKey": "Key rotation remains an explicit API operation; the dashboard can revoke and recreate keys.",
    "ParticipantPurgeController.previewParticipantPurge": "Partial collected-data purges are API-only protocol operations.",
    "ParticipantPurgeController.executeParticipantPurge": "Partial collected-data purges are API-only protocol operations.",
    "DataDeletionController.getOperation": "Researcher API keys poll one deletion operation; the dashboard lists them all.",
}
API_ONLY.update(dict.fromkeys([
    "AdminController.getCurrentUserPrincipals", "AdminController.getUserPrincipals",
    "AdminController.moveToEventStorage", "AdminController.reloadCache",
], "Published operator administration API; the dashboard does not administer storage or principal caches."))
API_ONLY.update(dict.fromkeys([
    "OrganizationController.createOrganization", "OrganizationController.getOrganization",
    "OrganizationController.getOrganizations", "AuthorizationsController.getAccessibleObjects",
    "PermissionsController.getAcl", "PermissionsController.getAclExplanation", "PermissionsController.getAcls",
    "PermissionsController.updateAcl", "PermissionsController.updateAcls",
    "PrincipalDirectoryController.addPrincipalToPrincipal", "PrincipalDirectoryController.deleteUserAccount",
    "PrincipalDirectoryController.getAvailableRoles", "PrincipalDirectoryController.getCurrentRoles",
    "PrincipalDirectoryController.getSecurablePrincipal", "PrincipalDirectoryController.removePrincipalFromPrincipal",
    "PrincipalDirectoryController.searchUsers", "PrincipalDirectoryController.syncCallingUser",
], "Published organization/identity/ACL administration API; controller parity and authorization enumeration preserve its contract."))
API_ONLY.update(dict.fromkeys([
    "StudyV4Controller.enrollV4", "StudyV4Controller.getEnrollmentPreviewV4",
    "StudyV4Controller.reportAndroidSensorAvailabilityV4", "StudyV4Controller.reportCollectionAcknowledgmentV4",
    "StudyV4Controller.uploadActivityRecognitionEventsV4", "StudyV4Controller.uploadAndroidSensorDataReceiptV4",
    "StudyV4Controller.uploadAndroidSensorDataV4", "StudyV4Controller.uploadAndroidUsageEventDataV4",
    "StudyV4Controller.uploadAppNetworkUsageV4", "StudyV4Controller.uploadAudioActivityV4",
    "StudyV4Controller.uploadAudioContentV4", "StudyV4Controller.uploadBatteryTelemetryV4",
    "StudyV4Controller.uploadConnectivityStateEventsV4", "StudyV4Controller.uploadDeviceSettingsV4",
    "StudyV4Controller.uploadDiagnosticsV4", "StudyV4Controller.uploadHealthMetricsV4",
    "StudyV4Controller.uploadInteractionEventsV4", "StudyV4Controller.uploadIosBatteryTelemetry",
    "StudyV4Controller.uploadIosConnectivityStateEvents", "StudyV4Controller.uploadIosHealthMetrics",
    "StudyV4Controller.uploadNotificationActivityV4", "StudyV4Controller.uploadScreenTimeDataV4",
    "StudyV4Controller.uploadSleepEventsV4", "MobileEnrollmentController.withdrawCurrentEnrollment",
    "MobileReminderController.getParticipationStatus", "MobileReminderController.getReminderSchedule",
], "Published native-device enrollment, consent, collection, and withdrawal protocol; Kotlin/iOS clients consume it outside the dashboard."))
API_ONLY.update({
    "AuthTokenController.oidcCallback": "The identity provider redirects the browser to the registered OIDC callback.",
    "AuthTokenController.oidcLogin": "Browser navigation begins the configured OIDC flow.",
    "AuthTokenController.setAuthCookie": "Published session bootstrap for existing bearer-token API integrations.",
    "AuthTokenController.testingLogin": "Explicit testing-login protocol, disabled by production configuration.",
    "CandidateController.registerCandidate": "Published CandidateApi preregistration contract retained for external API clients.",
    "ConcurrentEditFilter.revision": "Published HEAD revision reads let external writers obtain a strong If-Match token.",
    "EncryptionHealthService.encryptionHealth": "Authenticated operator API for encryption readiness; authorization and internal-contract tests enumerate it.",
    "InternalHealthController.live": "The selfhost readiness/probe scripts consume the internal liveness contract.",
    "InternalHealthController.ready": "The selfhost readiness/probe scripts consume the dependency readiness contract.",
    "JwksController.getJwks": "JWT verifiers fetch the published RS256 public keys.",
    "NotificationController.sendNotifications": "Retained NotificationApi command refuses unsupported participant delivery with 501; it never reports a successful no-op.",
    "NotificationController.updateNotificationStatus": "Twilio invokes the configured delivery-status callback.",
    "ParticipantFormAccessController.createAccessCode": "Native reminder clients issue participant form capabilities through the v4 alias.",
    "StudyComplianceController.triggerComplianceNotificationsForAllStudies": "Published operator API for a manual compliance notification run.",
    "StudyComplianceController.triggerStudyComplianceNotifications": "Published operator API for a selected-study compliance notification run.",
    "StudyController.destroyStudy": "Published StudyApi erasure operation; lifecycle/deletion callers also exercise it.",
    "StudyController.getAndroidDiagnostics": "The dashboard diagnostics URL builder and native diagnostics contract consume the filtered query.",
    "StudyController.getOrgStudies": "Published StudyApi organization study listing; external clients retain paged access.",
    "StudyController.getParticipantsData": "Published streaming export API; browser download navigation supplies the query outside fetch.",
    "StudyController.postParticipantsData": "Browser form navigation posts streaming exports outside the fetch request scanner.",
    "StudyController.getStudySetting": "Native collection workers read the public DataCollection specialization; researchers read other settings.",
    "StudyController.isKnownParticipant": "Published StudyApi participant verification contract retained for API clients.",
    "SurveyController.getDeviceUsageSurveyData": "Published participant-session/device-usage survey API retained for external survey clients.",
    "SurveyController.getAppsFilteredForStudyAppUsageSurvey": "Published filtered-app settings API; GET publishes the revision used by replacement.",
    "SurveyController.setAppsFilteredForStudyAppUsageSurvey": "Published filtered-app replacement API requires the read revision to prevent lost updates.",
    "SurveyController.filterAppForStudyAppUsageSurvey": "Published additive filtered-app update for external study setup clients.",
    "SurveyController.allowAppForStudyAppUsageSurvey": "Published subtractive filtered-app update for external study setup clients.",
    "SurveyController.getQuestionnaireResponses": "Published streaming questionnaire-response export API.",
    "SurveyController.postQuestionnaireResponses": "Browser form navigation posts questionnaire-response exports outside fetch.",
    "TimeUseDiaryController.getParticipantsTudSubmissions": "Published streaming participant diary export API.",
    "TimeUseDiaryController.postParticipantsTudSubmissions": "Browser form navigation posts participant diary exports outside fetch.",
    "TimeUseDiaryController.getStudyTUDSubmissions": "Published streaming whole-study diary export API.",
    "TimeUseDiaryController.postStudyTUDSubmissions": "Browser form navigation posts whole-study diary exports outside fetch.",
    "WebhookController.listWebhooks": "Published integration API lists study webhook registrations.",
    "WebhookController.getDeliveries": "Published integration API inspects bounded webhook delivery history.",
})


def canonical(path):
    path = re.sub(r"\$\{[^}]*\}", "{}", path)
    path = re.sub(r"\{[^}]*\}", "{}", path).split("?", 1)[0]
    for prefix in ("/chronicle/api/web", "/chronicle"):
        if path.startswith(prefix + "/"):
            path = path[len(prefix):]
            break
    return re.sub(r"^/v3(?=/)", "", path)


def uncovered(root):
    sources = sorted(path for path in (root / "chronicle-web/src/modern").rglob("*")
                     if path.suffix in {".ts", ".tsx"} and ".test." not in path.name and ".generated." not in path.name)
    result = subprocess.run(['bun', str(Path(__file__).with_name('endpoint-consumers.ts')), *map(str, sources)],
                            capture_output=True, text=True, check=True, timeout=30)
    consumers = {(request['method'], canonical(request['path'])) for request in json.loads(result.stdout)}
    inventory = root / "chronicle-server/src/test/resources/route-inventory.json"
    missing = []
    for route in json.loads(inventory.read_text()):
        operation = route["operation"]
        if (route["method"], canonical(route["path"])) not in consumers and operation not in API_ONLY:
            missing.append(f"{operation}: {route['method']} {canonical(route['path'])} has no caller or external API reason")
    return sorted(set(missing))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        fixtures = Path(__file__).resolve().parent / "fixtures/endpoint-consumers"
        assert len(uncovered(fixtures / "positive")) == 2, "Missing mutation and GET consumers must fail"
        assert not uncovered(fixtures / "negative"), "A real consumer must pass"
        assert len(uncovered(fixtures / "unused")) == 1, "Unused URL strings and objects must fail"
        assert len(uncovered(fixtures / "wrong-method")) == 1, "A request using the wrong method must fail"
        missing = uncovered(fixtures / "forwarded-pagination")
        assert len(missing) == 1 and missing[0].startswith("FutureController.unknownParticipantRoute:"), (
            "Nested wrappers must retain both real consumers and reject an unrelated non-network fetcher", missing)
        print("PASS endpoint consumer mutation fixtures")
        return 0
    missing = uncovered(args.root)
    for message in missing:
        print(message, file=sys.stderr)
    if not missing:
        print("PASS every production endpoint has a caller or external API contract")
    return bool(missing)


if __name__ == "__main__":
    raise SystemExit(main())

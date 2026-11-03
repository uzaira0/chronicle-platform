// ruleid: live-response-in-transaction
fun update(response: HttpServletResponse) { PinnedPlatformConnection.committing(pool, connection) { chain.doFilter(request, response) } }

// ok: live-response-in-transaction
fun update(response: HttpServletResponse) { val buffered = ContentCachingResponseWrapper(response); PinnedPlatformConnection.committing(pool, connection) { chain.doFilter(request, buffered) }; buffered.copyBodyToResponse() }



fun send(webhook: Webhooks, participantId: String) {
    val envelope = mapOf("subject" to participantId)
    // ruleid: raw-identifier-webhook-egress
    webhook.enqueueEvent(connection, study, event, envelope)
    val alias = participantId
    // ruleid: raw-identifier-webhook-egress
    webhook.fireEvent(study, event, mapOf("subject" to alias))
}

// ok: raw-identifier-webhook-egress
fun send(webhook: Webhooks, participantId: String) {
    val ref = ParticipantRef.fromParticipantId(participantId)
    webhook.enqueueEvent(connection, study, event, WebhookPayload.ParticipantEnrolled(ref, status))
    webhook.fireEvent(study, event, WebhookPayload.Test())
}



class Receiver : BroadcastReceiver() {
 @Throws(IllegalStateException::class)
 fun start(context: Context) {}
 override fun onReceive(context: Context, intent: Intent) {
  // ruleid: receiver-throwing-helper
  report(start(context))
 }
}

// ok: receiver-throwing-helper
class Receiver : BroadcastReceiver() {
 
 fun start(context: Context) {}
 override fun onReceive(context: Context, intent: Intent) {
  report(start(context))
 }
}



fun persist() {
    // ruleid: sql-exception-as-cause
    try { write() } catch (problem: SQLException) { throw IllegalStateException("retry", problem) }
    // ruleid: sql-exception-as-cause
    try { write() } catch (other: SQLException) { throw other }
}

// ok: sql-exception-as-cause
fun persist() {
    try { write() } catch (problem: SQLException) { throw SqlFailures.sanitize(problem) }
}



// ruleid: tautological-assertion
fun test() { assertEquals(value, value) }

// ok: tautological-assertion
fun test() {
assertEquals(AndroidSensorSetting(), AndroidSensorSetting())
assertEquals(AndroidDeviceSensorAvailability(), AndroidDeviceSensorAvailability())
}


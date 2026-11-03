import http from 'k6/http';
import { check } from 'k6';
import { prepareEnrollment, enrollInvitedDevice, signedMobileHeaders, uploadAcknowledged } from '../load/mobile-client.js';

/**
 * Shared helpers for Chronicle k6 performance tests.
 *
 * All scripts source BASE_URL and JWT_TOKEN from environment variables.
 */

export const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:40320';
export const JWT_TOKEN = __ENV.JWT_TOKEN || '';

export const HEALTH_URL = `${BASE_URL}/health`;
export const MANAGEMENT_URL = __ENV.MANAGEMENT_URL ? `${__ENV.MANAGEMENT_URL}/chronicle/api/web` : `${BASE_URL}/chronicle/v3`;
export const STUDY_LIST_URL = `${MANAGEMENT_URL}/study`;
const devices = new Map();
const deviceKey = (study, participant, device) => JSON.stringify([study, participant, device]);

export function authHeaders() {
  return {
    Authorization: `Bearer ${JWT_TOKEN}`,
    'Content-Type': 'application/json',
  };
}

export function publicHeaders() {
  return {
    'Content-Type': 'application/json',
  };
}

/**
 * Hit the public health endpoint (unauthenticated).
 * Returns the http response.
 */
export function checkHealth(tags) {
  const res = http.get(HEALTH_URL, {
    tags: Object.assign({ name: 'health' }, tags),
  });
  check(res, { 'health: status 200 or 204': r => r.status === 200 || r.status === 204 });
  return res;
}

/**
 * List studies (authenticated). Returns the http response.
 */
export function listStudies(tags) {
  const res = http.get(STUDY_LIST_URL, {
    headers: authHeaders(),
    tags: Object.assign({ name: 'list_studies' }, tags),
  });
  check(res, {
    'list studies: status 200': (r) => r.status === 200,
    'list studies: is array': (r) => {
      try {
        return Array.isArray(JSON.parse(r.body));
      } catch {
        return false;
      }
    },
  });
  return res;
}

/**
 * Get study detail by ID (authenticated).
 */
export function getStudy(studyId, tags) {
  const res = http.get(`${STUDY_LIST_URL}/${encodeURIComponent(studyId)}`, {
    headers: authHeaders(),
    tags: Object.assign({ name: 'get_study' }, tags),
  });
  check(res, {
    'study detail: status 200': (r) => r.status === 200,
  });
  return res;
}

/**
 * Get participants for a study (authenticated).
 */
export function getParticipants(studyId, tags) {
  const res = http.get(
    `${STUDY_LIST_URL}/${encodeURIComponent(studyId)}/participants`,
    {
      headers: authHeaders(),
      tags: Object.assign({ name: 'get_participants' }, tags),
    },
  );
  check(res, {
    'participants: status 200 or 403': (r) => r.status === 200 || r.status === 403,
  });
  return res;
}

/**
 * Get participant stats for a study (authenticated).
 */
export function getParticipantStats(studyId, tags) {
  const res = http.get(
    `${STUDY_LIST_URL}/${encodeURIComponent(studyId)}/participants/stats`,
    {
      headers: authHeaders(),
      tags: Object.assign({ name: 'get_participant_stats' }, tags),
    },
  );
  check(res, {
    'participant stats: status 200 or 403': (r) => r.status === 200 || r.status === 403,
  });
  return res;
}

function uploadAndroid(studyId, participantId, sourceRandomDeviceId, rows, suffix, name, tags) {
  const enrollment = devices.get(deviceKey(studyId, participantId, sourceRandomDeviceId));
  if (!enrollment) throw new Error('device must enroll and acknowledge consent before uploading');
  const url = `${BASE_URL}/chronicle/v4/study/${encodeURIComponent(studyId)}/participant/${encodeURIComponent(participantId)}/android${suffix}`;
  const data = rows;
  const payload = JSON.stringify(data);
  const res = http.post(url, payload, { headers: signedMobileHeaders(url, payload, enrollment.headers, __ENV.MOBILE_SIGNING_SECRET),
    tags: Object.assign({ name }, tags) });
  const accepted = check(res, { 'upload: every sample acknowledged': response => uploadAcknowledged(response, data, !suffix) });
  if (!accepted) throw new Error('upload did not acknowledge every generated sample');
  return res;
}

export function uploadAndroidUsageEvents(studyId, participantId, device, events, tags) {
  return uploadAndroid(studyId, participantId, device, events, '', 'upload_android_usage', tags);
}

export function uploadAndroidSensorData(studyId, participantId, device, samples, tags) {
  return uploadAndroid(studyId, participantId, device, samples, '/sensors', 'upload_android_sensors', tags);
}

export function enrollDevice(studyId, participantId, device, deviceInfo) {
  if (!__ENV.MOBILE_SIGNING_SECRET) throw new Error('MOBILE_SIGNING_SECRET is required for signed performance uploads');
  const study = `${STUDY_LIST_URL}/${encodeURIComponent(studyId)}`;
  const mobile = `${BASE_URL}/chronicle/v4/study/${encodeURIComponent(studyId)}/participant/${encodeURIComponent(participantId)}`;
  const fixture = prepareEnrollment(study, mobile, participantId, device, authHeaders(), deviceInfo);
  const enrolled = enrollInvitedDevice(fixture, __ENV.MOBILE_SIGNING_SECRET);
  devices.set(deviceKey(studyId, participantId, device), enrolled);
  return enrolled.response;
}

export { generateUsageEventBatch, generateSensorDataBatch, generateAndroidDevice } from '../load/mobile-client.js';

const API_BASE = '/chronicle/v3';
export function issueUrl(studyId: string, participantId: string) {
  return `${API_BASE}/study/${encodeURIComponent(studyId)}/participant/${encodeURIComponent(participantId)}/form-access-codes`;
}

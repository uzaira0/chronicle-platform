import { issueUrl } from './endpoints';

export const issueCode = (studyId: string, participantId: string) =>
  fetch(issueUrl(studyId, participantId), { method: 'POST' });

type PageFetch = (path: string) => unknown;

async function readAllPages(fetchPage: PageFetch, path: string) {
  return fetchPage(path);
}

async function readParticipantPages(load: PageFetch, path: string) {
  return readAllPages(load, path);
}

function loadParticipantMap(request: PageFetch, resource: string) {
  return readParticipantPages(request, resource);
}

export function stats(baseQuery: PageFetch, studyId: string) {
  return readParticipantPages(baseQuery, `/study/${studyId}/participants/stats`);
}

export function iosStatus(baseQuery: PageFetch, studyId: string) {
  return loadParticipantMap(baseQuery, `/study/${studyId}/participants/ios/upload-status`);
}

const unrelatedFetcher = (path: string) => path;
declare const studyId: string;
loadParticipantMap(unrelatedFetcher, `/study/${studyId}/participants/never-requested`);

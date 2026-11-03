type PageFetch = (path: string) => unknown;

function readAllPages(fetchPage: PageFetch, path: string) {
  return fetchPage(path);
}

function forward(load: PageFetch, path: string) {
  return readAllPages(load, path);
}

export function unresolved(baseQuery: PageFetch, unknownUrl: string) {
  return forward(baseQuery, unknownUrl);
}

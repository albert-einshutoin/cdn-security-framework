// Index only larger configurations; small policies keep the compact linear path.
export function buildPathIndex(groups: string[][], caseInsensitive: boolean): Record<string, number[]> | null {
  if (groups.reduce((sum, prefixes) => sum + prefixes.length, 0) < 32) return null;
  const index: Record<string, number[]> = Object.create(null);
  groups.forEach((prefixes, id) => {
    for (const prefix of prefixes) {
      const key = caseInsensitive ? prefix.toLowerCase() : prefix;
      const ids = index[key] || (index[key] = []);
      if (ids[ids.length - 1] !== id) ids.push(id);
    }
  });
  return index;
}

// A prefix matches at the existing '/' boundary, including trailing and doubled
// slashes. Sorting candidates preserves the policy's authentication AND order.
export const PATH_INDEX_HELPER = `
function pathCandidates(uri, index) {
  var found = [], seen = Object.create(null);
  function add(key) {
    var ids = Object.prototype.hasOwnProperty.call(index, key) ? index[key] : [];
    for (var j = 0; j < ids.length; j++) {
      if (!seen[ids[j]]) { seen[ids[j]] = true; found.push(ids[j]); }
    }
  }
  for (var i = uri.indexOf('/'); i !== -1; i = uri.indexOf('/', i + 1)) add(uri.slice(0, i));
  add(uri);
  return found.sort(function(a, b) { return a - b; });
}`;

// Response indexes only need membership; buildPathIndex never emits empty ID lists.
// Keep the ordered candidate collector above for authentication's AND checks.
export const PATH_MATCH_HELPER = `
function pathHasMatch(uri, index) {
  for (var i = uri.indexOf('/'); i !== -1; i = uri.indexOf('/', i + 1)) {
    if (Object.prototype.hasOwnProperty.call(index, uri.slice(0, i))) return true;
  }
  return Object.prototype.hasOwnProperty.call(index, uri);
}`;

/** New snapshots replace cached rows, except messages received during the fetch. */
export function mergeSnapshot<T extends { id: string }>(current: T[], snapshot: T[], updated: Set<string>): T[] {
  return [...new Map([...current, ...snapshot.filter(row => !updated.has(row.id))].map(row => [row.id, row])).values()];
}

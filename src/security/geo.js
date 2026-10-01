// Impossible-travel detection: same account "logging in" from places no traveller could reach in time.
const R = 6371; // km
const rad = (d) => (d * Math.PI) / 180;
export function haversineKm(a, b) {
  const dLat = rad(b.lat - a.lat), dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}
/** prev/curr: { lat, lon, t(ms) }. Default ceiling 900 km/h (airliner). Ignores tiny hops (GeoIP noise). */
export function impossibleTravel(prev, curr, { maxKmh = 900, minKm = 100 } = {}) {
  const km = haversineKm(prev, curr);
  if (km < minKm) return false;
  const hours = Math.max((curr.t - prev.t) / 3_600_000, 1 / 3600);
  return km / hours > maxKmh;
}

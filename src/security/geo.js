// Impossible travel: the same account logging in from places nobody could get between in the time.
const EARTH_RADIUS_KM = 6371;
const toRadians = (degrees) => (degrees * Math.PI) / 180;

export function haversineKm(a, b) {
  const dLat = toRadians(b.lat - a.lat);
  const dLon = toRadians(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2
    + Math.cos(toRadians(a.lat)) * Math.cos(toRadians(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

// prev and curr are { lat, lon, t } with t in milliseconds. 900 km/h is roughly an airliner.
// Short hops are ignored because GeoIP is only accurate to a city or so.
export function impossibleTravel(prev, curr, { maxKmh = 900, minKm = 100 } = {}) {
  const km = haversineKm(prev, curr);
  if (km < minKm) return false;

  const hours = Math.max((curr.t - prev.t) / 3_600_000, 1 / 3600);
  return km / hours > maxKmh;
}

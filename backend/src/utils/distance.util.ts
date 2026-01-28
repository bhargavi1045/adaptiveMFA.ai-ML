export interface Coordinates {
  latitude: number;
  longitude: number;
}

/**
 * Calculate distance between two points using Haversine formula
 * Returns distance in kilometers
 */
export const calculateDistance = (
  point1: Coordinates,
  point2: Coordinates
): number => {
  const R = 6371; // Earth's radius in kilometers
  
  const lat1 = toRadians(point1.latitude);
  const lat2 = toRadians(point2.latitude);
  const deltaLat = toRadians(point2.latitude - point1.latitude);
  const deltaLon = toRadians(point2.longitude - point1.longitude);

  const a =
    Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) *
    Math.sin(deltaLon / 2) * Math.sin(deltaLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  
  const distance = R * c;
  
  return Math.round(distance * 100) / 100; // Round to 2 decimal places
};

/**
 * Convert degrees to radians
 */
const toRadians = (degrees: number): number => {
  return degrees * (Math.PI / 180);
};

/**
 * Calculate travel speed in km/h
 */
export const calculateTravelSpeed = (
  distance: number, // in kilometers
  timeDiff: number  // in milliseconds
): number => {
  const hours = timeDiff / (1000 * 60 * 60);
  if (hours === 0) return Infinity;
  return distance / hours;
};

/**
 * Check if travel between two points is physically possible
 * Assumes maximum speed of 900 km/h (commercial airplane)
 */
export const isImpossibleTravel = (
  point1: Coordinates,
  point2: Coordinates,
  timeDiff: number, // in milliseconds
  maxSpeed: number = 900 // km/h
): boolean => {
  // If points are the same, travel is always possible
  if (point1.latitude === point2.latitude && point1.longitude === point2.longitude) {
    return false;
  }

  const distance = calculateDistance(point1, point2);
  const speed = calculateTravelSpeed(distance, timeDiff);
  
  return speed > maxSpeed;
};

/**
 * Get human-readable distance
 */
export const formatDistance = (kilometers: number): string => {
  if (kilometers < 1) {
    return `${Math.round(kilometers * 1000)} meters`;
  } else if (kilometers < 10) {
    return `${kilometers.toFixed(1)} km`;
  } else {
    return `${Math.round(kilometers)} km`;
  }
};

/**
 * Get human-readable time difference
 */
export const formatTimeDiff = (milliseconds: number): string => {
  const minutes = Math.floor(milliseconds / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    return `${days} day${days > 1 ? 's' : ''}`;
  } else if (hours > 0) {
    return `${hours} hour${hours > 1 ? 's' : ''}`;
  } else {
    return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  }
};

/**
 * Calculate the bearing between two points
 * Returns bearing in degrees (0-360)
 */
export const calculateBearing = (
  point1: Coordinates,
  point2: Coordinates
): number => {
  const lat1 = toRadians(point1.latitude);
  const lat2 = toRadians(point2.latitude);
  const deltaLon = toRadians(point2.longitude - point1.longitude);

  const y = Math.sin(deltaLon) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) -
            Math.sin(lat1) * Math.cos(lat2) * Math.cos(deltaLon);

  const bearing = Math.atan2(y, x);
  const degrees = (bearing * 180 / Math.PI + 360) % 360;

  return Math.round(degrees);
};

/**
 * Get compass direction from bearing
 */
export const getCompassDirection = (bearing: number): string => {
  const directions = ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'];
  const index = Math.round(bearing / 45) % 8;
  return directions[index];
};
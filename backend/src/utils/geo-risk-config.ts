export const GEO_RISK_CONFIG = {
  // High-risk countries (based on common fraud statistics)
  // Update this list based on your specific security requirements
  HIGH_RISK_COUNTRIES: [
    'NG', // Nigeria
    'GH', // Ghana
    'RU', // Russia
    'CN', // China
    'VN', // Vietnam
    'ID', // Indonesia
    'PK', // Pakistan
    'BD', // Bangladesh
    'RO', // Romania
    'UA', // Ukraine
  ],
  
  // Medium-risk countries
  MEDIUM_RISK_COUNTRIES: [
    'BR', // Brazil
    'IN', // India
    'PH', // Philippines
    'ZA', // South Africa
    'KE', // Kenya
    'MY', // Malaysia
    'TH', // Thailand
    'EG', // Egypt
    'TR', // Turkey
    'MX', // Mexico
  ],
  
  // Risk scores for different factors
  RISK_SCORES: {
    HIGH_RISK_COUNTRY: 30,
    MEDIUM_RISK_COUNTRY: 15,
    LOW_RISK_COUNTRY: 0,
    VPN_USAGE: 25,
    PROXY_USAGE: 25,
    NEW_LOCATION: 20,
    NEW_COUNTRY: 30,
    IMPOSSIBLE_TRAVEL: 50,
    UNUSUAL_DISTANCE: 20,
    FREQUENT_LOCATION_CHANGES: 15,
    FIRST_LOGIN_EVER: 5,
  },
  
  // Distance thresholds (in kilometers)
  DISTANCE_THRESHOLDS: {
    SAME_CITY: 50,
    SAME_REGION: 200,
    SAME_COUNTRY: 1000,
    DIFFERENT_COUNTRY: Infinity
  },
  
  // Maximum travel speeds (km/h)
  MAX_TRAVEL_SPEED: {
    COMMERCIAL_FLIGHT: 900,
    PRIVATE_JET: 950,
    SUPERSONIC: 2000,
    DEFAULT: 900
  },
  
  // Time windows for analysis
  TIME_WINDOWS: {
    RECENT_LOGIN_MINUTES: 60,
    LOCATION_MEMORY_DAYS: 30,
    TRAVEL_WINDOW_HOURS: 24,
    FREQUENT_CHANGE_WINDOW_DAYS: 7
  },

  // MFA requirements based on risk thresholds
  MFA_THRESHOLDS: {
    ALWAYS_REQUIRE: 60,      // Always require MFA above this score
    RECOMMEND: 40,            // Recommend but don't force MFA
    OPTIONAL: 20,             // MFA is optional
    NOT_REQUIRED: 0           // No MFA needed
  },

  // Login blocking thresholds
  BLOCK_THRESHOLDS: {
    IMMEDIATE: 80,            // Block immediately
    REQUIRE_VERIFICATION: 70, // Require email/SMS verification
    ALLOW_WITH_MFA: 40,       // Allow with MFA
    ALLOW: 0                  // Allow without restrictions
  }
};

export type CountryCode = string;

/**
 * Get risk level for a country
 */
export const getCountryRiskLevel = (countryCode: CountryCode): 'high' | 'medium' | 'low' => {
  if (GEO_RISK_CONFIG.HIGH_RISK_COUNTRIES.includes(countryCode)) {
    return 'high';
  }
  if (GEO_RISK_CONFIG.MEDIUM_RISK_COUNTRIES.includes(countryCode)) {
    return 'medium';
  }
  return 'low';
};

/**
 * Get risk score for a country
 */
export const getCountryRiskScore = (countryCode: CountryCode): number => {
  const level = getCountryRiskLevel(countryCode);
  
  switch (level) {
    case 'high':
      return GEO_RISK_CONFIG.RISK_SCORES.HIGH_RISK_COUNTRY;
    case 'medium':
      return GEO_RISK_CONFIG.RISK_SCORES.MEDIUM_RISK_COUNTRY;
    case 'low':
      return GEO_RISK_CONFIG.RISK_SCORES.LOW_RISK_COUNTRY;
  }
};

/**
 * Check if MFA should be required based on risk score
 */
export const shouldRequireMFA = (riskScore: number): boolean => {
  return riskScore >= GEO_RISK_CONFIG.MFA_THRESHOLDS.ALWAYS_REQUIRE;
};

/**
 * Check if login should be blocked based on risk score
 */
export const shouldBlockLogin = (riskScore: number): boolean => {
  return riskScore >= GEO_RISK_CONFIG.BLOCK_THRESHOLDS.IMMEDIATE;
};

/**
 * Get action recommendation based on risk score
 */
export const getActionRecommendation = (riskScore: number): string => {
  if (riskScore >= GEO_RISK_CONFIG.BLOCK_THRESHOLDS.IMMEDIATE) {
    return 'BLOCK';
  } else if (riskScore >= GEO_RISK_CONFIG.BLOCK_THRESHOLDS.REQUIRE_VERIFICATION) {
    return 'REQUIRE_VERIFICATION';
  } else if (riskScore >= GEO_RISK_CONFIG.MFA_THRESHOLDS.ALWAYS_REQUIRE) {
    return 'REQUIRE_MFA';
  } else if (riskScore >= GEO_RISK_CONFIG.MFA_THRESHOLDS.RECOMMEND) {
    return 'RECOMMEND_MFA';
  } else {
    return 'ALLOW';
  }
};
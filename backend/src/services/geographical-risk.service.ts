import { geolocationService, GeoLocation } from './geolocation.service';
import { LoginHistory, ILoginHistory } from '../models/loginHistory.model';
import { GEO_RISK_CONFIG, getCountryRiskScore } from '../utils/geo-risk-config';
import { calculateDistance, isImpossibleTravel } from '../utils/distance.util';

export interface GeographicalRiskAssessment {
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: string[];
  location: GeoLocation | null;
  recommendations: string[];
  requiresMFA: boolean;
  shouldBlock: boolean;
}

class GeographicalRiskService {
  /**
   * Assess geographical risk for a login attempt
   */
  async assessGeographicalRisk(
    userId: string,
    ip: string,
    forceRefresh = false
  ): Promise<GeographicalRiskAssessment> {
    const riskFactors: string[] = [];
    let riskScore = 0;

    // Skip risk assessment for localhost/development environments
    if (this.isDevelopmentEnvironment(ip)) {
      return {
        riskScore: 0,
        riskLevel: 'low',
        riskFactors: ['Development/local environment - risk assessment skipped'],
        location: null,
        recommendations: ['Allow login - development mode'],
        requiresMFA: false,
        shouldBlock: false
      };
    }

    // Get location from IP
    const location = await geolocationService.getLocationFromIP(ip, forceRefresh);
    
    if (!location) {
      return {
        riskScore: 50,
        riskLevel: 'medium',
        riskFactors: ['Unable to determine location'],
        location: null,
        recommendations: ['Require MFA', 'Manual review recommended'],
        requiresMFA: true,
        shouldBlock: false
      };
    }

    // Skip risk assessment for localhost (development)
    if (location.country === 'LOCAL') {
      return {
        riskScore: 0,
        riskLevel: 'low',
        riskFactors: ['Local development environment'],
        location,
        recommendations: ['Allow login'],
        requiresMFA: false,
        shouldBlock: false
      };
    }

    // 1. Assess country risk
    const countryRisk = getCountryRiskScore(location.country);
    if (countryRisk > 0) {
      riskScore += countryRisk;
      riskFactors.push(`Login from risk-assessed country: ${location.country}`);
    }

    // 2. Check for VPN/Proxy usage
    if (location.isVPN) {
      riskScore += GEO_RISK_CONFIG.RISK_SCORES.VPN_USAGE;
      riskFactors.push('VPN detected');
    }
    
    if (location.isProxy) {
      riskScore += GEO_RISK_CONFIG.RISK_SCORES.PROXY_USAGE;
      riskFactors.push('Proxy detected');
    }

    // 3. Check login history for patterns
    const recentLogin: ILoginHistory | null = await LoginHistory.findOne({
      userId,
      success: true,
      timestamp: {
        $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
      }
    })
    .sort({ timestamp: -1 })
    .exec();

    if (recentLogin) {
      // Check for new location
      if (location.city !== recentLogin.city || location.country !== recentLogin.country) {
        riskScore += GEO_RISK_CONFIG.RISK_SCORES.NEW_LOCATION;
        riskFactors.push(`New login location: ${location.city}, ${location.country}`);
      }

      // Check for impossible travel
      const timeDiff = Date.now() - recentLogin.timestamp.getTime();
      const distance = calculateDistance(
        { latitude: recentLogin.latitude, longitude: recentLogin.longitude },
        { latitude: location.latitude, longitude: location.longitude }
      );

      const impossible = isImpossibleTravel(
        { latitude: recentLogin.latitude, longitude: recentLogin.longitude },
        { latitude: location.latitude, longitude: location.longitude },
        timeDiff
      );

      if (impossible) {
        riskScore += GEO_RISK_CONFIG.RISK_SCORES.IMPOSSIBLE_TRAVEL;
        riskFactors.push(
          `Impossible travel detected: ${distance.toFixed(0)} km in ${(timeDiff / 60000).toFixed(0)} minutes`
        );
      }
    } else {
      // Check if user has any previous logins
      const anyPreviousLogin: ILoginHistory | null = await LoginHistory.findOne({
        userId,
        success: true
      })
      .sort({ timestamp: -1 })
      .exec();

      if (anyPreviousLogin) {
        // This is a new location but not the first login ever
        riskScore += GEO_RISK_CONFIG.RISK_SCORES.NEW_LOCATION;
        riskFactors.push('First login from this location');
      }
    }

    // 4. Check for frequent location changes
    const locationChangeCount = await this.getLocationChangeFrequency(userId, 7);
    if (locationChangeCount > 5) {
      riskScore += GEO_RISK_CONFIG.RISK_SCORES.FREQUENT_LOCATION_CHANGES;
      riskFactors.push(`Frequent location changes: ${locationChangeCount} in 7 days`);
    }

    // Cap risk score at 100
    riskScore = Math.min(riskScore, 100);

    // Determine risk level and recommendations
    const riskLevel = this.determineRiskLevel(riskScore);
    const requiresMFA = riskScore >= parseInt(process.env.REQUIRE_MFA_AT_RISK_SCORE || '40');
    const shouldBlock = riskScore >= parseInt(process.env.BLOCK_LOGIN_AT_RISK_SCORE || '80');
    const recommendations = this.generateRecommendations(riskScore, riskFactors);

    return {
      riskScore,
      riskLevel,
      riskFactors,
      location,
      recommendations,
      requiresMFA,
      shouldBlock
    };
  }

  /**
   * Get location change frequency for a user over specified days
   */
  private async getLocationChangeFrequency(userId: string, days: number = 7): Promise<number> {
    try {
      const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      
      const logins = await LoginHistory.find({
        userId,
        success: true,
        timestamp: { $gte: startDate }
      })
      .sort({ timestamp: 1 })
      .select('country city timestamp')
      .exec();

      if (logins.length < 2) {
        return 0;
      }

      let locationChanges = 0;
      for (let i = 1; i < logins.length; i++) {
        if (
          logins[i].city !== logins[i - 1].city ||
          logins[i].country !== logins[i - 1].country
        ) {
          locationChanges++;
        }
      }

      return locationChanges;
    } catch (error) {
      console.error('Error calculating location change frequency:', error);
      return 0;
    }
  }

  /**
   * Check if request is from development environment
   */
  private isDevelopmentEnvironment(ip: string): boolean {
    // Check for localhost IPs
    const localhostPatterns = [
      '127.0.0.1',
      'localhost',
      '::1',           // IPv6 localhost
      '0.0.0.0',
      '127.0.0.0/8'
    ];

    // Check if development mode is enabled
    if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test') {
      return localhostPatterns.some(pattern => {
        if (pattern.includes('/')) {
          // CIDR notation not implemented, simple string check
          return ip.startsWith(pattern.split('/')[0]);
        }
        return ip.includes(pattern);
      });
    }

    return false;
  }

  /**
   * Determine risk level from score
   */
  private determineRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }

  /**
   * Generate security recommendations based on risk assessment
   */
  private generateRecommendations(score: number, factors: string[]): string[] {
    const recommendations: string[] = [];

    if (score >= 80) {
      recommendations.push('Block login');
      recommendations.push('Send security alert to user');
      recommendations.push('Require additional verification');
      recommendations.push('Flag for manual review');
    } else if (score >= 60) {
      recommendations.push('Require MFA');
      recommendations.push('Send security notification');
      recommendations.push('Monitor subsequent activity');
    } else if (score >= 30) {
      recommendations.push('Recommend MFA');
      recommendations.push('Log for review');
    } else {
      recommendations.push('Allow login');
      recommendations.push('Standard monitoring');
    }

    if (factors.some(f => f.includes('VPN') || f.includes('Proxy'))) {
      recommendations.push('Review VPN/Proxy policy');
    }

    if (factors.some(f => f.includes('Impossible travel'))) {
      recommendations.push('Urgent: Flag for fraud investigation');
    }

    return recommendations;
  }

  /**
   * Save login attempt to history
   */
  async saveLoginHistory(
    userId: string,
    ip: string,
    userAgent: string,
    success: boolean,
    riskAssessment: GeographicalRiskAssessment,
    failureReason?: string,
    mfaRequired: boolean = false,
    mfaCompleted: boolean = false
  ): Promise<void> {
    try {
      if (!riskAssessment.location) {
        console.warn('No location data available for login history');
        return;
      }

      // Parse user agent to get device info
      const deviceInfo = this.parseUserAgent(userAgent);

      await LoginHistory.create({
        userId,
        ip,
        country: riskAssessment.location.country,
        region: riskAssessment.location.region,
        city: riskAssessment.location.city,
        latitude: riskAssessment.location.latitude,
        longitude: riskAssessment.location.longitude,
        timezone: riskAssessment.location.timezone,
        isVPN: riskAssessment.location.isVPN || false,
        isProxy: riskAssessment.location.isProxy || false,
        userAgent,
        deviceType: deviceInfo.deviceType,
        browser: deviceInfo.browser,
        os: deviceInfo.os,
        success,
        failureReason,
        mfaRequired,
        mfaCompleted,
        riskScore: riskAssessment.riskScore,
        riskFactors: riskAssessment.riskFactors,
        timestamp: new Date()
      });

      console.log('✅ Login history saved:', {
        userId,
        success,
        riskScore: riskAssessment.riskScore,
        location: `${riskAssessment.location.city}, ${riskAssessment.location.country}`
      });
    } catch (error) {
      console.error('❌ Failed to save login history:', error);
    }
  }

  /**
   * Parse user agent to extract device information
   */
  private parseUserAgent(userAgent: string): {
    deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown';
    browser: string;
    os: string;
  } {
    try {
      const UAParser = require('ua-parser-js');
      const parser = new UAParser(userAgent);
      const result = parser.getResult();

      let deviceType: 'mobile' | 'tablet' | 'desktop' | 'unknown' = 'unknown';
      
      if (result.device.type === 'mobile') {
        deviceType = 'mobile';
      } else if (result.device.type === 'tablet') {
        deviceType = 'tablet';
      } else if (result.device.type === undefined || result.device.type === '') {
        deviceType = 'desktop';
      }

      return {
        deviceType,
        browser: result.browser.name || 'Unknown',
        os: result.os.name || 'Unknown'
      };
    } catch (error) {
      console.error('Error parsing user agent:', error);
      return {
        deviceType: 'unknown',
        browser: 'Unknown',
        os: 'Unknown'
      };
    }
  }

  /**
   * Get user's login history
   */
  async getUserLoginHistory(
    userId: string,
    limit: number = 10
  ): Promise<ILoginHistory[]> {
    try {
      return await LoginHistory.find({ userId })
        .sort({ timestamp: -1 })
        .limit(limit)
        .exec();
    } catch (error) {
      console.error('Error fetching login history:', error);
      return [];
    }
  }

  /**
   * Get geographical statistics for a user
   */
  async getUserGeoStats(userId: string) {
    try {
      const stats = await LoginHistory.aggregate([
        { $match: { userId: userId } },
        {
          $group: {
            _id: null,
            uniqueCountries: { $addToSet: '$country' },
            uniqueCities: { $addToSet: '$city' },
            totalLogins: { $sum: 1 },
            successfulLogins: {
              $sum: { $cond: ['$success', 1, 0] }
            },
            failedLogins: {
              $sum: { $cond: ['$success', 0, 1] }
            },
            avgRiskScore: { $avg: '$riskScore' },
            vpnLogins: {
              $sum: { $cond: ['$isVPN', 1, 0] }
            }
          }
        }
      ]);

      return stats[0] || null;
    } catch (error) {
      console.error('Error fetching geo stats:', error);
      return null;
    }
  }
}

export const geographicalRiskService = new GeographicalRiskService();
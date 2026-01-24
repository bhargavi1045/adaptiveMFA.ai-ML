

export interface ContextFeatures {
  new_device: number;
  ip_change: number;
  login_hour: number;
  is_weekend?: number;
  is_night?: number;
  browser_automation_detected?: number;
}

export interface ContextAnalysisResult {
  isHighRisk: boolean;
  riskProbability: number;
  confidence: number;
  reasons: string[];
  metrics: Record<string, number>;
  recommendations: string[];
}

export interface LoginContext {
  ipAddress: string;
  deviceId: string;
  userAgent: string;
  timestamp: Date;
  geolocation?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
}

export class ContextAgent {
  private thresholds = {
    high_risk: 0.7,
    medium_risk: 0.5,
    night_start: 22,
    night_end: 6,
    unusual_hour_weight: 0.2
  };

  async analyze(
    contextData: ContextFeatures,
    loginContext: LoginContext,
    mlPrediction?: {
      is_high_risk: boolean;
      risk_probability: number;
      confidence: number;
    },
    userHistory?: Array<{
      ipAddress: string;
      deviceId: string;
      timestamp: Date;
      country?: string;
    }>
  ): Promise<ContextAnalysisResult> {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};
    const recommendations: string[] = [];

    let isHighRisk = false;
    let riskProbability = 0;

    if (mlPrediction) {
      isHighRisk = mlPrediction.is_high_risk;
      riskProbability = mlPrediction.risk_probability;
      reasons.push(`ML risk probability: ${(riskProbability * 100).toFixed(1)}%`);
    } else {

      const calculated = this.calculateContextRisk(contextData, loginContext, userHistory);
      riskProbability = calculated.probability;
      isHighRisk = calculated.isHighRisk;
      reasons.push('Using fallback context analysis');
    }

    metrics['risk_probability'] = riskProbability;

    if (contextData.new_device === 1) {
      reasons.push('Login from new/unrecognized device');
      metrics['new_device'] = 1;
      recommendations.push('Verify device ownership');
    }

    if (contextData.ip_change === 1) {
      reasons.push('IP address changed from last login');
      metrics['ip_change'] = 1;
      
      if (userHistory && userHistory.length > 0) {
        const lastLogin = userHistory[0];
        const timeDiff = (loginContext.timestamp.getTime() - lastLogin.timestamp.getTime()) / (1000 * 60);
        
        if (timeDiff < 60) {
          reasons.push(`IP changed within ${timeDiff.toFixed(0)} minutes`);
          recommendations.push('Potential account takeover - verify immediately');
        }
      }
    }

    const timeAnalysis = this.analyzeLoginTime(contextData.login_hour);
    if (timeAnalysis.unusual) {
      reasons.push(timeAnalysis.reason);
      metrics['unusual_time'] = 1;
    }

    if (loginContext.geolocation && userHistory && userHistory.length > 0) {
      const locationAnalysis = this.analyzeLocationChange(
        loginContext.geolocation,
        userHistory
      );
      if (locationAnalysis.suspicious) {
        reasons.push(locationAnalysis.reason);
        metrics['location_change'] = 1;
        recommendations.push('Verify user location');
      }
    }

    if (contextData.browser_automation_detected === 1) {
      reasons.push('Browser automation/bot detected');
      metrics['automation'] = 1;
      recommendations.push('Require CAPTCHA verification');
      isHighRisk = true;
      riskProbability = Math.max(riskProbability, 0.8);
    }

    if (isHighRisk) {
      recommendations.push('Additional verification strongly recommended');
      if (contextData.new_device === 1 && contextData.ip_change === 1) {
        recommendations.push('Multiple risk factors - require strong authentication');
      }
    } else if (riskProbability >= this.thresholds.medium_risk) {
      recommendations.push('Monitor session for suspicious activity');
    } else {
      recommendations.push('Context appears normal for this user');
    }

    const confidence = this.calculateConfidence(
      mlPrediction?.confidence,
      userHistory
    );

    return {
      isHighRisk,
      riskProbability,
      confidence,
      reasons,
      metrics,
      recommendations
    };
  }

  private calculateContextRisk(
    data: ContextFeatures,
    context: LoginContext,
    history?: Array<{ ipAddress: string; deviceId: string; timestamp: Date }>
  ): { probability: number; isHighRisk: boolean } {
    let riskScore = 0;
    const factors = [];

    if (data.new_device === 1) {
      riskScore += 0.3;
      factors.push('new_device');
    }

    if (data.ip_change === 1) {
      riskScore += 0.2;
      factors.push('ip_change');
    }

    const hour = data.login_hour;
    if (hour < this.thresholds.night_end || hour >= this.thresholds.night_start) {
      riskScore += this.thresholds.unusual_hour_weight;
      factors.push('unusual_time');
    }

    if (data.is_weekend === 1 && history) {
      const weekendLogins = history.filter(h => {
        const day = h.timestamp.getDay();
        return day === 0 || day === 6;
      });
      const weekendRatio = weekendLogins.length / history.length;
      
      if (weekendRatio < 0.2) {
        riskScore += 0.1;
        factors.push('unusual_weekend_login');
      }
    }

    if (data.browser_automation_detected === 1) {
      riskScore += 0.4;
      factors.push('automation');
    }

    const probability = Math.min(riskScore, 1.0);
    const isHighRisk = probability >= this.thresholds.high_risk;

    return { probability, isHighRisk };
  }

 
  private analyzeLoginTime(hour: number): { unusual: boolean; reason: string } {
    if (hour < this.thresholds.night_end) {
      return {
        unusual: true,
        reason: `Login during early morning hours (${hour}:00)`
      };
    }

    if (hour >= this.thresholds.night_start) {
      return {
        unusual: true,
        reason: `Login during late night hours (${hour}:00)`
      };
    }

    return { unusual: false, reason: '' };
  }


  private analyzeLocationChange(
    currentLocation: {
      country?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
    },
    history: Array<{ timestamp: Date; country?: string }>
  ): { suspicious: boolean; reason: string } {
    if (!currentLocation.country) {
      return { suspicious: false, reason: '' };
    }

    const recentLogins = history
      .filter(h => {
        const hoursAgo = (Date.now() - h.timestamp.getTime()) / (1000 * 60 * 60);
        return hoursAgo < 24;
      })
      .filter(h => h.country);

    if (recentLogins.length === 0) {
      return { suspicious: false, reason: '' };
    }

    const lastCountry = recentLogins[0].country;
    if (lastCountry && lastCountry !== currentLocation.country) {
      const timeDiff = (Date.now() - recentLogins[0].timestamp.getTime()) / (1000 * 60 * 60);
      
      if (timeDiff < 12) {
        return {
          suspicious: true,
          reason: `Location changed from ${lastCountry} to ${currentLocation.country} within ${timeDiff.toFixed(1)} hours`
        };
      }
    }

    return { suspicious: false, reason: '' };
  }


  private calculateConfidence(
    mlConfidence?: number,
    history?: Array<any>
  ): number {
    const factors: number[] = [];

    if (mlConfidence !== undefined) {
      factors.push(mlConfidence);
    } else {
      factors.push(0.7); 
    }

    if (history && history.length > 30) {
      factors.push(0.95);
    } else if (history && history.length > 10) {
      factors.push(0.8);
    } else {
      factors.push(0.6);
    }

    return factors.reduce((a, b) => a + b, 0) / factors.length;
  }
}

export default ContextAgent;
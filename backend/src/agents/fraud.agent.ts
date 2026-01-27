

export interface FraudAnalysisResult {
  isFraud: boolean;
  fraudProbability: number;
  confidence: number;
  reasons: string[];
  metrics: Record<string, number>;
  recommendations: string[];
  threatLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface FraudIndicators {
  loginFrequency24h: number;
  uniqueIPs24h: number;
  failedAttemptsRatio: number;
  deviceConsistencyScore: number;
  impossibleTravel: boolean;
  automationDetected: boolean;
  countryChanges24h: number;
}

export class FraudAgent {
  private thresholds = {
    fraud_probability: 0.6,
    high_fraud: 0.8,
    critical_fraud: 0.9,
    max_login_frequency: 10,
    max_unique_ips: 3,
    max_failed_ratio: 0.3,
    min_device_consistency: 0.5
  };

  async analyze(
    indicators: FraudIndicators,
    mlPrediction?: {
      is_fraud: boolean;
      fraud_probability: number;
      confidence: number;
    },
    loginHistory?: Array<{
      timestamp: Date;
      ipAddress: string;
      deviceId: string;
      success: boolean;
      country?: string;
    }>
  ): Promise<FraudAnalysisResult> {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};
    const recommendations: string[] = [];

    let isFraud = false;
    let fraudProbability = 0;

    if (mlPrediction) {
      isFraud = mlPrediction.is_fraud;
      fraudProbability = mlPrediction.fraud_probability;
      reasons.push(`ML Fraud Probability: ${(fraudProbability * 100).toFixed(1)}%`);
      
      if (isFraud) {
        reasons.push('ML model flagged as potential fraud');
      }
    } else {
    
      const calculated = this.calculateFraudScore(indicators, loginHistory);
      fraudProbability = calculated.probability;
      isFraud = calculated.isFraud;
      reasons.push('Using fallback fraud detection');
    }

    metrics['fraud_probability'] = fraudProbability;

    const indicatorAnalysis = this.analyzeIndicators(indicators);
    reasons.push(...indicatorAnalysis.reasons);
    Object.assign(metrics, indicatorAnalysis.metrics);

    if (loginHistory) {
      const takeoverCheck = this.checkAccountTakeover(loginHistory);
      if (takeoverCheck.suspected) {
        reasons.push(takeoverCheck.reason);
        metrics['takeover_risk'] = 1;
        recommendations.push('ALERT: Potential account takeover detected');
        isFraud = true;
        fraudProbability = Math.max(fraudProbability, 0.9);
      }
    }

    if (indicators.impossibleTravel) {
      reasons.push('Impossible travel detected - login from distant location too quickly');
      metrics['impossible_travel'] = 1;
      recommendations.push('Verify user location immediately');
      isFraud = true;
      fraudProbability = Math.max(fraudProbability, 0.85);
    }

    if (indicators.automationDetected) {
      reasons.push('Automated/bot activity detected');
      metrics['automation'] = 1;
      recommendations.push('Block automated access - require CAPTCHA');
      fraudProbability = Math.max(fraudProbability, 0.8);
    }

    const threatLevel = this.determineThreatLevel(fraudProbability, indicators);
    metrics['threat_level'] = this.threatLevelToNumber(threatLevel);

    this.generateRecommendations(
      threatLevel,
      fraudProbability,
      indicators,
      recommendations
    );

    const confidence = this.calculateConfidence(mlPrediction, loginHistory);
    metrics['confidence'] = confidence;

    return {
      isFraud,
      fraudProbability,
      confidence,
      reasons,
      metrics,
      recommendations,
      threatLevel
    };
  }

  
  private calculateFraudScore(
    indicators: FraudIndicators,
    history?: Array<any>
  ): { probability: number; isFraud: boolean } {
    let score = 0;
    const weights = {
      loginFrequency: 0.15,
      uniqueIPs: 0.15,
      failedAttempts: 0.20,
      deviceConsistency: 0.15,
      impossibleTravel: 0.25,
      automation: 0.10
    };

    if (indicators.loginFrequency24h > this.thresholds.max_login_frequency) {
      const excess = (indicators.loginFrequency24h - this.thresholds.max_login_frequency) / 10;
      score += Math.min(excess * weights.loginFrequency, weights.loginFrequency);
    }

    if (indicators.uniqueIPs24h > this.thresholds.max_unique_ips) {
      const excess = (indicators.uniqueIPs24h - this.thresholds.max_unique_ips) / 5;
      score += Math.min(excess * weights.uniqueIPs, weights.uniqueIPs);
    }

    if (indicators.failedAttemptsRatio > this.thresholds.max_failed_ratio) {
      score += indicators.failedAttemptsRatio * weights.failedAttempts;
    }

    if (indicators.deviceConsistencyScore < this.thresholds.min_device_consistency) {
      score += (1 - indicators.deviceConsistencyScore) * weights.deviceConsistency;
    }

    if (indicators.impossibleTravel) {
      score += weights.impossibleTravel;
    }

    if (indicators.automationDetected) {
      score += weights.automation;
    }

    const probability = Math.min(score, 1.0);
    const isFraud = probability >= this.thresholds.fraud_probability;

    return { probability, isFraud };
  }

  
  private analyzeIndicators(
    indicators: FraudIndicators
  ): { reasons: string[]; metrics: Record<string, number> } {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};

    metrics['login_frequency_24h'] = indicators.loginFrequency24h;
    if (indicators.loginFrequency24h > this.thresholds.max_login_frequency) {
      reasons.push(`Abnormally high login frequency: ${indicators.loginFrequency24h} attempts in 24h`);
    }

    metrics['unique_ips_24h'] = indicators.uniqueIPs24h;
    if (indicators.uniqueIPs24h > this.thresholds.max_unique_ips) {
      reasons.push(`Multiple IP addresses: ${indicators.uniqueIPs24h} different IPs in 24h`);
    }

    metrics['failed_attempts_ratio'] = indicators.failedAttemptsRatio;
    if (indicators.failedAttemptsRatio > this.thresholds.max_failed_ratio) {
      reasons.push(`High failed login ratio: ${(indicators.failedAttemptsRatio * 100).toFixed(1)}%`);
    }

    metrics['device_consistency'] = indicators.deviceConsistencyScore;
    if (indicators.deviceConsistencyScore < this.thresholds.min_device_consistency) {
      reasons.push('Low device consistency - frequent device changes');
    }

    metrics['country_changes_24h'] = indicators.countryChanges24h;
    if (indicators.countryChanges24h > 2) {
      reasons.push(`Multiple country changes: ${indicators.countryChanges24h} in 24h`);
    }

    return { reasons, metrics };
  }


  private checkAccountTakeover(
    history: Array<{
      timestamp: Date;
      ipAddress: string;
      deviceId: string;
      success: boolean;
    }>
  ): { suspected: boolean; reason: string } {
    if (history.length < 2) {
      return { suspected: false, reason: '' };
    }

    const recent = history.slice(0, 10);

    const failedAttempts = recent.filter(h => !h.success);
    const successfulAttempts = recent.filter(h => h.success);

    if (failedAttempts.length > 3 && successfulAttempts.length > 0) {
      const lastFailed = failedAttempts[0];
      const firstSuccess = successfulAttempts[0];

      if (
        lastFailed.deviceId !== firstSuccess.deviceId ||
        lastFailed.ipAddress !== firstSuccess.ipAddress
      ) {
        return {
          suspected: true,
          reason: 'Pattern suggests account takeover: multiple failures followed by success from different device'
        };
      }
    }

    const oldPattern = history.slice(10, 30);
    if (oldPattern.length > 10) {
      const oldDevices = new Set(oldPattern.map(h => h.deviceId));
      const newDevices = new Set(recent.map(h => h.deviceId));
      
      const overlap = [...oldDevices].filter(d => newDevices.has(d));
      if (overlap.length === 0) {
        return {
          suspected: true,
          reason: 'Complete change in device pattern - possible account takeover'
        };
      }
    }

    return { suspected: false, reason: '' };
  }

  private determineThreatLevel(
    fraudProbability: number,
    indicators: FraudIndicators
  ): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (fraudProbability >= this.thresholds.critical_fraud || 
        (indicators.impossibleTravel && indicators.automationDetected)) {
      return 'CRITICAL';
    }
    
    if (fraudProbability >= this.thresholds.high_fraud || indicators.impossibleTravel) {
      return 'HIGH';
    }
    
    if (fraudProbability >= this.thresholds.fraud_probability) {
      return 'MEDIUM';
    }
    
    if (fraudProbability >= 0.3) {
      return 'LOW';
    }
    
    return 'NONE';
  }

  private generateRecommendations(
    threatLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    fraudProbability: number,
    indicators: FraudIndicators,
    recommendations: string[]
  ): void {
    switch (threatLevel) {
      case 'CRITICAL':
        recommendations.push('CRITICAL: Block login immediately');
        recommendations.push('Alert security team and user');
        recommendations.push('Require account verification via email/phone');
        recommendations.push('Consider temporary account lock');
        break;

      case 'HIGH':
        recommendations.push('HIGH: Deny access and require strong authentication');
        recommendations.push('Send security alert to user');
        recommendations.push('Require email/SMS verification');
        break;

      case 'MEDIUM':
        recommendations.push('MEDIUM: Require additional authentication');
        recommendations.push('Log for security review');
        recommendations.push('Consider rate limiting');
        break;

      case 'LOW':
        recommendations.push('LOW: Monitor closely for escalation');
        recommendations.push('Consider soft MFA challenge');
        break;

      case 'NONE':
        recommendations.push('No fraud indicators detected');
        break;
    }

    if (indicators.automationDetected) {
      recommendations.push('Implement CAPTCHA or similar bot detection');
    }

    if (indicators.uniqueIPs24h > 5) {
      recommendations.push('Flag account for security review - unusual IP pattern');
    }
  }


  private threatLevelToNumber(level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): number {
    const mapping = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    return mapping[level];
  }

  
  private calculateConfidence(
    mlPrediction?: { confidence: number },
    history?: Array<any>
  ): number {
    const factors: number[] = [];

    if (mlPrediction) {
      factors.push(mlPrediction.confidence);
    } else {
      factors.push(0.7);
    }

    if (history) {
      if (history.length > 30) {
        factors.push(0.9);
      } else if (history.length > 10) {
        factors.push(0.75);
      } else {
        factors.push(0.6);
      }
    } else {
      factors.push(0.5);
    }

    return factors.reduce((a, b) => a + b, 0) / factors.length;
  }
}

export default FraudAgent;
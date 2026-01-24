
export interface RiskAnalysisResult {
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  reasons: string[];
  metrics: Record<string, number>;
  recommendations: string[];
}

export interface RiskFactors {
  behaviorScore: number;
  contextScore: number;
  fraudScore: number;
  accountHistoryScore: number;
}

export class RiskAgent {
  private thresholds = {
    low: 0.3,
    medium: 0.5,
    high: 0.7,
    critical: 0.85
  };

  private weights = {
    behavior: 0.25,
    context: 0.25,
    fraud: 0.30,
    accountHistory: 0.20
  };


  async analyze(
    riskFactors: RiskFactors,
    mlPrediction?: {
      risk_score: number;
      risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    },
    additionalContext?: {
      failedLoginAttempts: number;
      accountAge: number;
      totalLogins: number;
      averageRiskScore: number;
    }
  ): Promise<RiskAnalysisResult> {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};
    const recommendations: string[] = [];

    let riskScore = 0;
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';

    if (mlPrediction) {
      riskScore = mlPrediction.risk_score;
      riskLevel = mlPrediction.risk_level;
      reasons.push(`ML Risk Score: ${(riskScore * 100).toFixed(1)}%`);
      reasons.push(`ML Risk Level: ${riskLevel}`);
    } else {

      const calculated = this.calculateRiskScore(riskFactors, additionalContext);
      riskScore = calculated.score;
      riskLevel = calculated.level;
      reasons.push('Using fallback risk calculation');
    }

    metrics['overall_risk_score'] = riskScore;
    metrics['behavior_score'] = riskFactors.behaviorScore;
    metrics['context_score'] = riskFactors.contextScore;
    metrics['fraud_score'] = riskFactors.fraudScore;
    metrics['account_history_score'] = riskFactors.accountHistoryScore;

    const componentAnalysis = this.analyzeRiskComponents(riskFactors);
    reasons.push(...componentAnalysis.reasons);

    if (additionalContext) {
      const historyAnalysis = this.analyzeAccountHistory(additionalContext);
      reasons.push(...historyAnalysis.reasons);
      Object.assign(metrics, historyAnalysis.metrics);
    }

    switch (riskLevel) {
      case 'CRITICAL':
        recommendations.push('CRITICAL: Immediate action required');
        recommendations.push('Require strongest available MFA method');
        recommendations.push('Consider temporary account lock');
        recommendations.push('Alert security team');
        break;

      case 'HIGH':
        recommendations.push('HIGH RISK: Additional verification required');
        recommendations.push('Require multi-factor authentication');
        recommendations.push('Monitor subsequent actions closely');
        break;

      case 'MEDIUM':
        recommendations.push('MEDIUM RISK: Elevated monitoring recommended');
        recommendations.push('Consider step-up authentication');
        recommendations.push('Log for security review');
        break;

      case 'LOW':
        recommendations.push('LOW RISK: Standard authentication acceptable');
        recommendations.push('Continue normal monitoring');
        break;
    }

    if (riskFactors.fraudScore > 0.7) {
      recommendations.push('High fraud indicators - verify user identity');
    }

    if (riskFactors.behaviorScore > 0.7) {
      recommendations.push('Unusual behavior detected - additional checks needed');
    }

    if (riskFactors.contextScore > 0.7) {
      recommendations.push('High-risk context - verify device and location');
    }

    const confidence = this.calculateConfidence(mlPrediction, additionalContext);
    metrics['confidence'] = confidence;

    return {
      riskScore,
      riskLevel,
      confidence,
      reasons,
      metrics,
      recommendations
    };
  }

 
  private calculateRiskScore(
    factors: RiskFactors,
    context?: {
      failedLoginAttempts: number;
      accountAge: number;
      totalLogins: number;
      averageRiskScore: number;
    }
  ): { score: number; level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' } {
    
    let score =
      factors.behaviorScore * this.weights.behavior +
      factors.contextScore * this.weights.context +
      factors.fraudScore * this.weights.fraud +
      factors.accountHistoryScore * this.weights.accountHistory;

    
    if (context) {
      if (context.accountAge < 30) {
        score += 0.1;
      }

      if (context.failedLoginAttempts > 5) {
        score += 0.15;
      } else if (context.failedLoginAttempts > 2) {
        score += 0.05;
      }

      if (context.averageRiskScore > 0.6) {
        score += 0.1;
      }
    }

    score = Math.max(0, Math.min(1, score));

    let level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    if (score >= this.thresholds.critical) {
      level = 'CRITICAL';
    } else if (score >= this.thresholds.high) {
      level = 'HIGH';
    } else if (score >= this.thresholds.medium) {
      level = 'MEDIUM';
    } else {
      level = 'LOW';
    }

    return { score, level };
  }

  private analyzeRiskComponents(
    factors: RiskFactors
  ): { reasons: string[] } {
    const reasons: string[] = [];

    if (factors.behaviorScore > 0.7) {
      reasons.push(`High behavioral risk: ${(factors.behaviorScore * 100).toFixed(1)}%`);
    } else if (factors.behaviorScore > 0.5) {
      reasons.push(`Moderate behavioral risk: ${(factors.behaviorScore * 100).toFixed(1)}%`);
    }

    if (factors.contextScore > 0.7) {
      reasons.push(`High contextual risk: ${(factors.contextScore * 100).toFixed(1)}%`);
    } else if (factors.contextScore > 0.5) {
      reasons.push(`Moderate contextual risk: ${(factors.contextScore * 100).toFixed(1)}%`);
    }

    if (factors.fraudScore > 0.7) {
      reasons.push(`High fraud risk: ${(factors.fraudScore * 100).toFixed(1)}%`);
    } else if (factors.fraudScore > 0.5) {
      reasons.push(`Moderate fraud risk: ${(factors.fraudScore * 100).toFixed(1)}%`);
    }

    if (factors.accountHistoryScore > 0.7) {
      reasons.push(`Poor account history: ${(factors.accountHistoryScore * 100).toFixed(1)}%`);
    }

    return { reasons };
  }


  private analyzeAccountHistory(context: {
    failedLoginAttempts: number;
    accountAge: number;
    totalLogins: number;
    averageRiskScore: number;
  }): { reasons: string[]; metrics: Record<string, number> } {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};

    if (context.failedLoginAttempts > 5) {
      reasons.push(`${context.failedLoginAttempts} recent failed login attempts`);
      metrics['failed_logins'] = context.failedLoginAttempts;
    }

    if (context.accountAge < 7) {
      reasons.push(`New account (${context.accountAge} days old)`);
      metrics['account_age_days'] = context.accountAge;
    }

    if (context.totalLogins < 5) {
      reasons.push('Limited login history');
      metrics['total_logins'] = context.totalLogins;
    }

    if (context.averageRiskScore > 0.6) {
      reasons.push(`Historical risk pattern: ${(context.averageRiskScore * 100).toFixed(1)}%`);
      metrics['avg_historical_risk'] = context.averageRiskScore;
    }

    return { reasons, metrics };
  }


  private calculateConfidence(
    mlPrediction?: { risk_score: number; risk_level: string },
    context?: {
      failedLoginAttempts: number;
      accountAge: number;
      totalLogins: number;
      averageRiskScore: number;
    }
  ): number {
    const factors: number[] = [];

    if (mlPrediction) {
      factors.push(0.9);
    } else {
      factors.push(0.7);
    }

    if (context) {
      if (context.totalLogins > 50) {
        factors.push(0.95);
      } else if (context.totalLogins > 20) {
        factors.push(0.85);
      } else if (context.totalLogins > 10) {
        factors.push(0.75);
      } else {
        factors.push(0.6);
      }

      if (context.accountAge > 90) {
        factors.push(0.9);
      } else if (context.accountAge > 30) {
        factors.push(0.8);
      } else {
        factors.push(0.6);
      }
    } else {
      factors.push(0.5);
    }

    return factors.reduce((a, b) => a + b, 0) / factors.length;
  }


  getRiskLevelDescription(level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'): string {
    const descriptions = {
      LOW: 'Low risk - Standard authentication is acceptable',
      MEDIUM: 'Medium risk - Enhanced monitoring recommended',
      HIGH: 'High risk - Additional authentication required',
      CRITICAL: 'Critical risk - Immediate action and strongest authentication required'
    };
    return descriptions[level];
  }
}

export default RiskAgent;
/**
 * Decision Agent
 * Makes final MFA decision based on all agent analyses
 */

import { BehaviorAgent } from './behavior.agent';
import { ContextAgent } from './context.agent';
import { RiskAgent } from './risk.agent';
import { FraudAgent } from './fraud.agent';

export interface MFADecision {
  mfaRequired: boolean;
  decision: 'ALLOW' | 'REQUIRE_MFA' | 'REQUIRE_STRONG_MFA' | 'DENY' | 'MONITOR';
  confidence: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  reasons: string[];
  recommendations: string[];
  allowedMFAMethods?: ('totp' | 'sms' | 'email' | 'biometric' | 'hardware_key')[];
  expiresIn?: number;
  agentDecisions: {
    behavior: any;
    context: any;
    risk: any;
    fraud: any;
  };
}

export interface DecisionContext {
  behaviorAnalysis: any;
  contextAnalysis: any;
  riskAnalysis: any;
  fraudAnalysis: any;
  userProfile: {
    mfaEnabled: boolean;
    isTrustedDevice: boolean;
    accountAge: number;
  };
}

export class DecisionAgent {
  private behaviorAgent: BehaviorAgent;
  private contextAgent: ContextAgent;
  private riskAgent: RiskAgent;
  private fraudAgent: FraudAgent;

  private weights = {
    behavior: 0.20,
    context: 0.20,
    risk: 0.35,
    fraud: 0.25
  };

  constructor() {
    this.behaviorAgent = new BehaviorAgent();
    this.contextAgent = new ContextAgent();
    this.riskAgent = new RiskAgent();
    this.fraudAgent = new FraudAgent();
  }

  /**
   * Make final MFA decision based on all agent analyses
   */
  async decide(context: DecisionContext): Promise<MFADecision> {
    const reasons: string[] = [];
    const recommendations: string[] = [];

    // Extract key metrics from each agent
    const metrics = {
      behaviorScore: context.behaviorAnalysis.anomalyScore,
      contextScore: context.contextAnalysis.riskProbability,
      riskScore: context.riskAnalysis.riskScore,
      fraudScore: context.fraudAnalysis.fraudProbability
    };

    // Calculate weighted overall score
    const overallScore =
      metrics.behaviorScore * this.weights.behavior +
      metrics.contextScore * this.weights.context +
      metrics.riskScore * this.weights.risk +
      metrics.fraudScore * this.weights.fraud;

    // Get risk level from risk agent
    const riskLevel = context.riskAnalysis.riskLevel;

    // Collect reasons from all agents
    if (context.behaviorAnalysis.isAnomaly) {
      reasons.push('Behavioral anomaly detected');
      reasons.push(...context.behaviorAnalysis.reasons.slice(0, 2));
    }

    if (context.contextAnalysis.isHighRisk) {
      reasons.push('High-risk login context');
      reasons.push(...context.contextAnalysis.reasons.slice(0, 2));
    }

    if (context.fraudAnalysis.isFraud) {
      reasons.push('Fraud indicators present');
      reasons.push(...context.fraudAnalysis.reasons.slice(0, 2));
    }

    reasons.push(...context.riskAnalysis.reasons.slice(0, 2));

    // Decision rules
    let decision: 'ALLOW' | 'REQUIRE_MFA' | 'REQUIRE_STRONG_MFA' | 'DENY' | 'MONITOR';
    let mfaRequired = false;
    let allowedMethods: ('totp' | 'sms' | 'email' | 'biometric' | 'hardware_key')[] = [];
    let expiresIn: number | undefined;

    // Rule 1: DENY - Critical fraud or very high risk
    if (
      context.fraudAnalysis.threatLevel === 'CRITICAL' ||
      (context.fraudAnalysis.isFraud && context.fraudAnalysis.fraudProbability > 0.9) ||
      riskLevel === 'CRITICAL'
    ) {
      decision = 'DENY';
      mfaRequired = false;
      reasons.push('Access denied due to critical risk level');
      recommendations.push('Block access immediately');
      recommendations.push('Alert security team and user');
      recommendations.push('Require account verification');
    }
    // Rule 2: REQUIRE_STRONG_MFA - High fraud or critical risk
    else if (
      context.fraudAnalysis.threatLevel === 'HIGH' ||
      riskLevel === 'CRITICAL' ||
      (context.fraudAnalysis.isFraud && context.fraudAnalysis.fraudProbability > 0.8) ||
      overallScore > 0.85
    ) {
      decision = 'REQUIRE_STRONG_MFA';
      mfaRequired = true;
      allowedMethods = ['totp', 'hardware_key'];
      expiresIn = 300; // 5 minutes
      reasons.push('Strong authentication required due to high risk');
      recommendations.push('Use strongest available MFA method');
      recommendations.push('Consider biometric verification');
    }
    // Rule 3: REQUIRE_MFA - Medium-high risk
    else if (
      riskLevel === 'HIGH' ||
      context.fraudAnalysis.threatLevel === 'MEDIUM' ||
      context.behaviorAnalysis.anomalyScore > 0.7 ||
      context.contextAnalysis.isHighRisk ||
      overallScore > 0.7 ||
      context.userProfile.mfaEnabled
    ) {
      decision = 'REQUIRE_MFA';
      mfaRequired = true;
      allowedMethods = ['totp', 'sms', 'email'];
      expiresIn = 600; // 10 minutes
      reasons.push('Additional authentication required');
      recommendations.push('Complete MFA verification');
    }
    // Rule 4: MONITOR - Medium risk
    else if (
      riskLevel === 'MEDIUM' ||
      overallScore > 0.5 ||
      context.behaviorAnalysis.anomalyScore > 0.5
    ) {
      decision = 'MONITOR';
      mfaRequired = false;
      reasons.push('Medium risk detected - access granted with monitoring');
      recommendations.push('Monitor subsequent actions closely');
      recommendations.push('Consider enabling MFA');
    }
    // Rule 5: ALLOW - Low risk
    else {
      decision = 'ALLOW';
      mfaRequired = false;
      reasons.push('Risk level acceptable for direct access');
      recommendations.push('Continue standard monitoring');
    }

    // Trusted device exception
    if (
      context.userProfile.isTrustedDevice &&
      riskLevel !== 'CRITICAL' &&
      context.fraudAnalysis.threatLevel !== 'CRITICAL' &&
      !context.fraudAnalysis.isFraud
    ) {
      if (decision === 'REQUIRE_MFA') {
        decision = 'ALLOW';
        mfaRequired = false;
        reasons.push('Trusted device - MFA waived');
        recommendations.push('Device recognized and trusted');
      }
    }

    // Always require MFA if user has it enabled (unless DENY)
    if (context.userProfile.mfaEnabled && decision !== 'DENY') {
      if (decision === 'ALLOW' || decision === 'MONITOR') {
        decision = 'REQUIRE_MFA';
        mfaRequired = true;
        allowedMethods = ['totp', 'sms', 'email'];
        reasons.push('MFA enforced by user settings');
      }
    }

    // Calculate overall confidence
    const confidence = this.calculateOverallConfidence(
      context.behaviorAnalysis.confidence,
      context.contextAnalysis.confidence,
      context.riskAnalysis.confidence,
      context.fraudAnalysis.confidence
    );

    // Collect all recommendations
    recommendations.push(
      ...context.behaviorAnalysis.recommendations.slice(0, 2),
      ...context.contextAnalysis.recommendations.slice(0, 2),
      ...context.riskAnalysis.recommendations.slice(0, 2),
      ...context.fraudAnalysis.recommendations.slice(0, 2)
    );

    // Remove duplicates
    const uniqueReasons = [...new Set(reasons)];
    const uniqueRecommendations = [...new Set(recommendations)];

    return {
      mfaRequired,
      decision,
      confidence,
      riskLevel,
      riskScore: overallScore,
      reasons: uniqueReasons,
      recommendations: uniqueRecommendations,
      allowedMFAMethods: allowedMethods.length > 0 ? allowedMethods : undefined,
      expiresIn,
      agentDecisions: {
        behavior: context.behaviorAnalysis,
        context: context.contextAnalysis,
        risk: context.riskAnalysis,
        fraud: context.fraudAnalysis
      }
    };
  }

  /**
   * Calculate overall confidence from all agents
   */
  private calculateOverallConfidence(
    behaviorConf: number,
    contextConf: number,
    riskConf: number,
    fraudConf: number
  ): number {
    return (
      behaviorConf * this.weights.behavior +
      contextConf * this.weights.context +
      riskConf * this.weights.risk +
      fraudConf * this.weights.fraud
    );
  }

  /**
   * Adjust agent weights (for fine-tuning)
   */
  setWeights(weights: {
    behavior?: number;
    context?: number;
    risk?: number;
    fraud?: number;
  }): void {
    if (weights.behavior !== undefined) this.weights.behavior = weights.behavior;
    if (weights.context !== undefined) this.weights.context = weights.context;
    if (weights.risk !== undefined) this.weights.risk = weights.risk;
    if (weights.fraud !== undefined) this.weights.fraud = weights.fraud;

    // Normalize weights to sum to 1
    const total =
      this.weights.behavior +
      this.weights.context +
      this.weights.risk +
      this.weights.fraud;

    if (total !== 1) {
      this.weights.behavior /= total;
      this.weights.context /= total;
      this.weights.risk /= total;
      this.weights.fraud /= total;
    }
  }

  /**
   * Get current weights
   */
  getWeights() {
    return { ...this.weights };
  }
}

export default DecisionAgent;

export interface BehaviorFeatures {
  keystroke_interval_ms: number;
  mouse_speed_px_s: number;
  session_duration_s: number;
  click_rate: number;
  keystroke_variance?: number;
  pages_visited?: number;
  automation_detected?: number;
}

export interface BehaviorAnalysisResult {
  isAnomaly: boolean;
  anomalyScore: number;
  confidence: number;
  reasons: string[];
  metrics: Record<string, number>;
  recommendations: string[];
}

export class BehaviorAgent {
  private thresholds = {
    anomaly_score: 0.7,
    high_anomaly: 0.85,
    keystroke_min: 50,
    keystroke_max: 500,
    mouse_speed_min: 100,
    mouse_speed_max: 2000,
    session_min: 5,
    automation_threshold: 0.8
  };

 
  async analyze(
    behaviorData: BehaviorFeatures,
    mlPrediction?: {
      is_anomaly: boolean;
      anomaly_score: number;
      confidence: number;
    },
    historicalBehavior?: BehaviorFeatures[]
  ): Promise<BehaviorAnalysisResult> {
    const reasons: string[] = [];
    const metrics: Record<string, number> = {};
    const recommendations: string[] = [];

    let isAnomaly = false;
    let anomalyScore = 0;

    if (mlPrediction) {
      isAnomaly = mlPrediction.is_anomaly;
      anomalyScore = mlPrediction.anomaly_score;
      reasons.push(`ML anomaly score: ${(anomalyScore * 100).toFixed(1)}%`);
    } else {

      const calculated = this.calculateAnomalyScore(behaviorData, historicalBehavior);
      anomalyScore = calculated.score;
      isAnomaly = calculated.isAnomaly;
      reasons.push('Using fallback behavior analysis');
    }

    metrics['anomaly_score'] = anomalyScore;


    const keystrokeAnalysis = this.analyzeKeystrokePattern(behaviorData);
    if (keystrokeAnalysis.suspicious) {
      reasons.push(keystrokeAnalysis.reason);
      metrics['keystroke_anomaly'] = 1;
    }

    const mouseAnalysis = this.analyzeMouseBehavior(behaviorData);
    if (mouseAnalysis.suspicious) {
      reasons.push(mouseAnalysis.reason);
      metrics['mouse_anomaly'] = 1;
    }

    if (behaviorData.automation_detected && behaviorData.automation_detected > 0) {
      reasons.push('Browser automation detected');
      metrics['automation_detected'] = 1;
      recommendations.push('Potential bot activity - require CAPTCHA');
      isAnomaly = true;
      anomalyScore = Math.max(anomalyScore, 0.9);
    }

    if (behaviorData.session_duration_s < this.thresholds.session_min) {
      reasons.push(`Unusually short session: ${behaviorData.session_duration_s}s`);
      metrics['short_session'] = 1;
    }

    if (behaviorData.click_rate > 2.0) {
      reasons.push('Abnormally high click rate');
      metrics['high_click_rate'] = behaviorData.click_rate;
    } else if (behaviorData.click_rate < 0.1 && behaviorData.session_duration_s > 30) {
      reasons.push('Unusually low interaction rate');
      metrics['low_click_rate'] = behaviorData.click_rate;
    }

    if (isAnomaly) {
      if (anomalyScore >= this.thresholds.high_anomaly) {
        recommendations.push('High behavioral anomaly - require additional verification');
      } else {
        recommendations.push('Monitor user activity for suspicious patterns');
      }
    } else {
      recommendations.push('Behavior patterns match expected profile');
    }

    const confidence = this.calculateConfidence(
      mlPrediction?.confidence,
      historicalBehavior
    );

    return {
      isAnomaly,
      anomalyScore,
      confidence,
      reasons,
      metrics,
      recommendations
    };
  }


  private analyzeKeystrokePattern(
    data: BehaviorFeatures
  ): { suspicious: boolean; reason: string } {
    const interval = data.keystroke_interval_ms;

    if (interval < this.thresholds.keystroke_min) {
      return {
        suspicious: true,
        reason: `Abnormally fast typing: ${interval}ms interval`
      };
    }

    if (interval > this.thresholds.keystroke_max) {
      return {
        suspicious: true,
        reason: `Abnormally slow typing: ${interval}ms interval`
      };
    }

    if (data.keystroke_variance !== undefined) {
      if (data.keystroke_variance < 0.05) {
        return {
          suspicious: true,
          reason: 'Keystroke timing too consistent (possible automation)'
        };
      }
      if (data.keystroke_variance > 1.0) {
        return {
          suspicious: true,
          reason: 'Highly irregular keystroke pattern'
        };
      }
    }

    return { suspicious: false, reason: '' };
  }

  private analyzeMouseBehavior(
    data: BehaviorFeatures
  ): { suspicious: boolean; reason: string } {
    const speed = data.mouse_speed_px_s;

    if (speed < this.thresholds.mouse_speed_min) {
      return {
        suspicious: true,
        reason: `Abnormally slow mouse movement: ${speed.toFixed(0)}px/s`
      };
    }

    if (speed > this.thresholds.mouse_speed_max) {
      return {
        suspicious: true,
        reason: `Abnormally fast mouse movement: ${speed.toFixed(0)}px/s`
      };
    }

    return { suspicious: false, reason: '' };
  }

  private calculateAnomalyScore(
    current: BehaviorFeatures,
    historical?: BehaviorFeatures[]
  ): { score: number; isAnomaly: boolean } {
    let score = 0;
    let anomalyCount = 0;
    const checks = [];

    if (
      current.keystroke_interval_ms < this.thresholds.keystroke_min ||
      current.keystroke_interval_ms > this.thresholds.keystroke_max
    ) {
      anomalyCount++;
    }
    checks.push(1);

    if (
      current.mouse_speed_px_s < this.thresholds.mouse_speed_min ||
      current.mouse_speed_px_s > this.thresholds.mouse_speed_max
    ) {
      anomalyCount++;
    }
    checks.push(1);

    if (current.session_duration_s < this.thresholds.session_min) {
      anomalyCount++;
    }
    checks.push(1);

    if (current.automation_detected && current.automation_detected > 0) {
      anomalyCount += 2; 
      checks.push(2);
    }

    const totalWeight = checks.reduce((a, b) => a + b, 0);
    score = anomalyCount / totalWeight;

    if (historical && historical.length > 5) {
      const deviation = this.calculateDeviation(current, historical);
      score = (score + deviation) / 2;
    }

    const isAnomaly = score >= this.thresholds.anomaly_score;

    return { score, isAnomaly };
  }

 
  private calculateDeviation(
    current: BehaviorFeatures,
    historical: BehaviorFeatures[]
  ): number {
    const avgKeystroke =
      historical.reduce((sum, h) => sum + h.keystroke_interval_ms, 0) /
      historical.length;
    const avgMouseSpeed =
      historical.reduce((sum, h) => sum + h.mouse_speed_px_s, 0) /
      historical.length;

    const keystrokeDev =
      Math.abs(current.keystroke_interval_ms - avgKeystroke) / avgKeystroke;
    const mouseSpeedDev =
      Math.abs(current.mouse_speed_px_s - avgMouseSpeed) / avgMouseSpeed;

    return (keystrokeDev + mouseSpeedDev) / 2;
  }


  private calculateConfidence(
    mlConfidence?: number,
    historicalData?: BehaviorFeatures[]
  ): number {
    const factors: number[] = [];

    if (mlConfidence !== undefined) {
      factors.push(mlConfidence);
    } else {
      factors.push(0.6); 
    }

    if (historicalData && historicalData.length > 20) {
      factors.push(0.9);
    } else if (historicalData && historicalData.length > 10) {
      factors.push(0.7);
    } else {
      factors.push(0.5);
    }

    return factors.reduce((a, b) => a + b, 0) / factors.length;
  }
}

export default BehaviorAgent;
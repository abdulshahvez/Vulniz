import React from 'react';

/**
 * Animated circular score gauge using SVG.
 */
export default function ScoreGauge({ score = 0, riskLevel = '', riskColor = '#00d4ff' }) {
  const radius = 78;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  const bgForRisk = (color) => `${color}18`;

  return (
    <div className="score-gauge">
      <div className="score-gauge__ring">
        <svg className="score-gauge__svg" width="180" height="180" viewBox="0 0 180 180">
          <circle className="score-gauge__bg" cx="90" cy="90" r={radius} />
          <circle
            className="score-gauge__fill"
            cx="90" cy="90" r={radius}
            stroke={riskColor}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="score-gauge__value">
          <div className="score-gauge__number" style={{ color: riskColor }}>
            {score}
          </div>
          <div className="score-gauge__label">/ 100</div>
        </div>
      </div>
      <div
        className="score-gauge__risk"
        style={{ background: bgForRisk(riskColor), color: riskColor }}
      >
        {riskLevel}
      </div>
    </div>
  );
}

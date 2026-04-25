import React from 'react';

export default function LandingInfo() {
  return (
    <div className="landing-info animate-in">
      <div className="landing-hero">
        <h2 className="landing-hero__title">
          Secure Your APIs <span>Before They Do.</span>
        </h2>
        <p className="landing-hero__subtitle">
          Advanced automated security testing designed to uncover vulnerabilities
          like SQL Injection, XSS, and Authentication Bypasses in your REST APIs.
        </p>
      </div>

      <div className="landing-features">
        <div className="feature-card card">
          <div className="feature-card__icon">⚡</div>
          <h3 className="feature-card__title">Lightning Fast Scans</h3>
          <p className="feature-card__desc">
            Our engine performs parallelized attacks across multiple vectors to identify
            vulnerabilities in seconds, not hours.
          </p>
        </div>

        <div className="feature-card card">
          <div className="feature-card__icon">🤖</div>
          <h3 className="feature-card__title">AI-Powered Fixes</h3>
          <p className="feature-card__desc">
            Go beyond simple detection. Get context-aware, production-ready code snippets
            and OWASP-aligned remediation steps.
          </p>
        </div>

        <div className="feature-card card">
          <div className="feature-card__icon">📊</div>
          <h3 className="feature-card__title">Actionable Reports</h3>
          <p className="feature-card__desc">
            Generate professional, exportable PDF security reports complete with risk scoring
            and detailed finding breakdowns.
          </p>
        </div>

        <div className="feature-card card">
          <div className="feature-card__icon">🛡️</div>
          <h3 className="feature-card__title">Comprehensive Coverage</h3>
          <p className="feature-card__desc">
            Test for OWASP Top 10 vulnerabilities including Injection, Broken Access Control,
            Security Misconfigurations, and more.
          </p>
        </div>
      </div>

      <div className="landing-how-it-works card">
        <div className="card__title">
          <span className="card__title-icon">🔍</span>
          How It Works
        </div>
        <div className="steps-container">
          <div className="step">
            <div className="step__number">1</div>
            <div className="step__content">
              <h4>Provide Target</h4>
              <p>Enter the URL of the API endpoint you want to test and select your attack vectors.</p>
            </div>
          </div>
          <div className="step-connector"></div>
          <div className="step">
            <div className="step__number">2</div>
            <div className="step__content">
              <h4>Simulate Attacks</h4>
              <p>Our engine runs a barrage of payloads and analyzes responses for anomalies in real-time.</p>
            </div>
          </div>
          <div className="step-connector"></div>
          <div className="step">
            <div className="step__number">3</div>
            <div className="step__content">
              <h4>Remediate</h4>
              <p>Review the detailed security score, vulnerability breakdown, and apply suggested fixes.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

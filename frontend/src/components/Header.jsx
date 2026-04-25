import React from 'react';

export default function Header() {
  return (
    <header className="header">
      <div className="header__logo">
        <div className="header__icon">🛡</div>
        <h1 className="header__title">
          <span>Vulniz</span>
        </h1>
      </div>
      <div className="header__badge">v1.0 • Security Testing Platform</div>
    </header>
  );
}

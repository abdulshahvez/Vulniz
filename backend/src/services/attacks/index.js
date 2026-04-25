/**
 * Attack Module Registry
 * ──────────────────────
 * Central barrel file that maps attack type names to their runner functions.
 * The scan engine imports this map so that modules can be invoked dynamically.
 */

import { runSqlInjection } from './sql-injection.js';
import { runXss } from './xss.js';
import { runRateLimit } from './rate-limit.js';
import { runHeaderSecurity } from './header-security.js';
import { runAuthBypass } from './auth-bypass.js';

/** @type {Record<string, (url: string, opts?: object) => Promise<object>>} */
const attackModules = {
  'sql-injection': runSqlInjection,
  'xss': runXss,
  'rate-limit': runRateLimit,
  'header-security': runHeaderSecurity,
  'auth-bypass': runAuthBypass,
};

/** All available attack type names */
export const ATTACK_TYPES = Object.keys(attackModules);

/** Retrieve a runner by name */
export function getAttackRunner(type) {
  return attackModules[type] || null;
}

export default attackModules;

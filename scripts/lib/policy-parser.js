'use strict';

/**
 * Extracts unique principals from an AWS resource policy JSON string.
 * Handles Principal as string ("*"), object ({ AWS: [...], Service: [...], Federated: [...] }),
 * or array. Only extracts from Allow statements.
 *
 * @param {string} policyJson - JSON string of the resource policy
 * @returns {string[]} Array of unique principal identifiers
 */
function extractPolicyPrincipals(policyJson) {
  if (!policyJson) return [];
  try {
    const doc = typeof policyJson === 'string' ? JSON.parse(policyJson) : policyJson;
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [];
    const principals = new Set();

    for (const stmt of statements) {
      if (stmt.Effect !== 'Allow') continue;
      const principal = stmt.Principal;
      if (!principal) continue;

      if (typeof principal === 'string') {
        principals.add(principal);
      } else if (typeof principal === 'object') {
        for (const key of ['AWS', 'Service', 'Federated']) {
          const val = principal[key];
          if (!val) continue;
          if (typeof val === 'string') principals.add(val);
          else if (Array.isArray(val)) val.forEach((v) => principals.add(v));
        }
      }
    }
    return [...principals];
  } catch {
    return [];
  }
}

module.exports = { extractPolicyPrincipals };

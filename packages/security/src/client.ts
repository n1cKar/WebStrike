/**
 * Client-safe subset of WebStrike security: pure host/path matching used for
 * live UI feedback. Import from `@webstrike/security/client` in the browser.
 * The server remains the sole authority on whether a request may proceed.
 */
export {
  hostMatchesPattern,
  isBlockedHost,
  isSystemBlockedHostname,
  normalizeHost,
  normalizePattern,
  previewScope,
  type ClientScopeCheck,
  type DomainPatternMatch,
} from "./match";
// Shared Signals SETs every SDK's SecurityEventVerifier must read the same way
// (security-event-vectors.json): a fixed RSA key's public JWKS, valid SETs
// of each event type Touchque sends and the parsed result, and refused ones
// with the RFC 8935 error code. Run: node fixtures/generate-security-event-vectors.mjs
import { generateKeyPairSync, createSign, randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const ISSUER = 'https://sso.touchque.example';
const AUDIENCE = 'https://receiver.example.com';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'tq-ssf-1', alg: 'RS256', use: 'sig' };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const IAT = 1793500000;

function sign(claims, { header = {}, key = privateKey } = {}) {
  const h = b64({ alg: 'RS256', typ: 'secevent+jwt', kid: 'tq-ssf-1', ...header });
  const p = b64(claims);
  const s = createSign('RSA-SHA256').update(`${h}.${p}`).sign(key).toString('base64url');
  return `${h}.${p}.${s}`;
}
const base = (uri, payload, extra = {}) => ({
  iss: ISSUER, jti: randomUUID(), iat: IAT, aud: AUDIENCE, sub_id: { format: 'email', email: 'ada@acme.example' },
  events: { [uri]: payload }, ...extra,
});
const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';

const validSpecs = [
  ['session-revoked', `${CAEP}session-revoked`, { event_timestamp: IAT, initiating_entity: 'policy', reason_admin: { en: 'The person said a sign-in was not theirs' } }, { txn: 'K7P2QX' }],
  ['credential-change', `${CAEP}credential-change`, { event_timestamp: IAT, initiating_entity: 'user', credential_type: 'password', change_type: 'update' }, {}],
  ['device-compliance-change', `${CAEP}device-compliance-change`, { event_timestamp: IAT, initiating_entity: 'policy', previous_status: 'compliant', current_status: 'not-compliant' }, {}],
  ['account-disabled', `${RISC}account-disabled`, { event_timestamp: IAT, initiating_entity: 'admin' }, { aud: [AUDIENCE, 'https://other.example'] }],
  ['credential-compromise', `${RISC}credential-compromise`, { event_timestamp: IAT, initiating_entity: 'policy', credential_type: 'password' }, {}],
  ['verification', `${SSF}verification`, { state: 'abc123' }, { sub_id: { format: 'opaque', id: 'stream-1' } }],
  [null, 'https://example.com/event-type/custom', { note: 'unknown types are passed on' }, {}],
];
const valid = validSpecs.map(([name, uri, payload, extra]) => {
  const claims = base(uri, payload, extra);
  return {
    name: name || 'custom',
    token: sign(claims),
    expect: {
      jti: claims.jti, issuer: ISSUER, audience: Array.isArray(claims.aud) ? claims.aud : [claims.aud], issuedAt: IAT,
      txn: claims.txn || null, subject: claims.sub_id, type: uri, name, claims: payload,
    },
  };
});

const ok = base(`${CAEP}session-revoked`, { event_timestamp: IAT });
const [h, p] = sign(ok).split('.');
const invalid = [
  { name: 'another audience', token: sign({ ...ok, aud: 'https://someone-else.example' }), error: 'invalid_audience' },
  { name: 'another issuer', token: sign({ ...ok, iss: 'https://evil.example' }), error: 'invalid_issuer' },
  { name: 'an unknown key', token: sign(ok, { header: { kid: 'nope' } }), error: 'invalid_key' },
  { name: 'signed by another key', token: sign(ok, { key: other }), error: 'invalid_key' },
  { name: 'a changed payload', token: `${h}.${b64({ ...ok, sub_id: { format: 'email', email: 'eve@evil.example' } })}.${sign(ok).split('.')[2]}`, error: 'invalid_key' },
  { name: 'not a SET (typ JWT)', token: sign(ok, { header: { typ: 'JWT' } }), error: 'invalid_request' },
  { name: 'two events in one SET', token: sign({ ...ok, events: { ...ok.events, [`${RISC}account-disabled`]: {} } }), error: 'invalid_request' },
  { name: 'alg HS256', token: sign(ok, { header: { alg: 'HS256' } }), error: 'invalid_key' },
  { name: 'issued in the future', token: sign({ ...ok, iat: 4102444800 }), error: 'invalid_request' },
  { name: 'not a JWT', token: 'abc.def', error: 'invalid_request' },
];

writeFileSync(new URL('./security-event-vectors.json', import.meta.url), `${JSON.stringify({ issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [jwk] }, valid, invalid }, null, 2)}\n`);
console.log(`security-event-vectors.json: ${valid.length} valid, ${invalid.length} refused`);

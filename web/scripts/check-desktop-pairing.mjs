import assert from 'node:assert/strict';

import { encodeDesktopPairingString } from '../src/utils/desktopPairing.ts';

const invite = {
  id: 'invite-test',
  token: 'one-time-test-token',
  relay: 'relay.example.com:8443',
  pin: 'test-pin',
  listen_port: 443,
  expires_at: '2026-10-09T12:00:00Z',
  bootstrap_url: 'https://relay.example.com:9444/api/bootstrap/desktop/v2',
  protocol_version: 2,
};

const expectedKeys = ['bootstrap_url', 'expires_at', 'invite'];
for (const version of [1, 2]) {
  const bootstrapURL = version === 1
    ? 'https://relay.example.com:9444/api/bootstrap/desktop'
    : invite.bootstrap_url;
  const code = encodeDesktopPairingString({ ...invite, bootstrap_url: bootstrapURL, protocol_version: version });
  const prefix = `nomifun-relay-pair:v${version}:`;
  assert.ok(code.startsWith(prefix));
  const payload = JSON.parse(Buffer.from(code.slice(prefix.length), 'base64url').toString('utf8'));
  assert.deepEqual(Object.keys(payload).toSorted(), expectedKeys);
  assert.equal(payload.bootstrap_url, bootstrapURL);
  assert.equal(payload.invite, invite.token);
  assert.equal(payload.expires_at, invite.expires_at);
}

// A missing server address must never create a code pointing at the administrator's browser.
assert.throws(() => encodeDesktopPairingString({ ...invite, bootstrap_url: '' }));
console.log('✓ Desktop pairing envelopes use the server address and preserve v1/v2 fields');

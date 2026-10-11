import type { DesktopPairingInvite } from '@/api/types';

/** Only the relay's configured public address can be handed to another computer. */
export function encodeDesktopPairingString(invite: DesktopPairingInvite): string {
  if (!invite.bootstrap_url) throw new Error('Desktop bootstrap URL is not configured');
  const payload = JSON.stringify({
    bootstrap_url: invite.bootstrap_url,
    invite: invite.token,
    expires_at: invite.expires_at,
  });
  const bytes = new TextEncoder().encode(payload);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `nomifun-relay-pair:v${invite.protocol_version ?? 1}:${encoded}`;
}

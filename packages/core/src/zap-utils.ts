import { getZapEndpoint, makeZapRequest, getSatoshisAmountFromBolt11 } from 'nostr-tools/nip57'
import type { NostrEvent, EventTemplate } from 'nostr-tools'

/**
 * Check if a profile metadata object has a lightning address (lud16 or lud06)
 */
export function hasLightningAddress(
  metadata: { lud16?: string; lud06?: string } | null | undefined
): boolean {
  if (!metadata) return false
  return !!(metadata.lud16 || metadata.lud06)
}

export interface ZapRequestParams {
  recipientPubkey: string
  amount: number // in sats
  comment?: string
  relays: string[]
  event?: NostrEvent // The actual event to zap (includes d tag for addressable events)
  timestamp?: number // Video timestamp in seconds (for timestamped zaps)
}

/**
 * Fetch the LNURL pay endpoint from a user's profile
 */
export async function getRecipientZapEndpoint(profile: NostrEvent): Promise<string | null> {
  return getZapEndpoint(profile)
}

/**
 * Create an unsigned zap request event template
 */
export function createZapRequest(params: ZapRequestParams): EventTemplate {
  const { recipientPubkey, amount, comment, relays, event, timestamp } = params

  const amountMsats = amount * 1000

  let template: EventTemplate
  if (event) {
    // Zapping an event - pass the actual event so d tag is preserved for addressable events
    template = makeZapRequest({
      event,
      amount: amountMsats,
      comment,
      relays,
    })
  } else {
    // Zapping a profile
    template = makeZapRequest({
      pubkey: recipientPubkey,
      amount: amountMsats,
      comment,
      relays,
    })
  }

  // Add timestamp tag if provided (for video timestamped zaps)
  if (timestamp !== undefined && timestamp >= 0) {
    template.tags = [...template.tags, ['timestamp', Math.floor(timestamp).toString()]]
  }

  return template
}

/**
 * Request an invoice from the LNURL callback
 */
export async function requestInvoice(
  callback: string,
  amount: number, // in sats
  zapRequest: NostrEvent
): Promise<string> {
  const amountMsats = amount * 1000

  const url = new URL(callback)
  url.searchParams.set('amount', amountMsats.toString())
  // URLSearchParams.set() automatically URL-encodes the value, so don't encode manually
  url.searchParams.set('nostr', JSON.stringify(zapRequest))

  const response = await fetch(url.toString())
  if (!response.ok) {
    throw new Error(`LNURL request failed: ${response.status}`)
  }

  const data = await response.json()
  if (data.status === 'ERROR') {
    throw new Error(data.reason || 'LNURL request failed')
  }

  if (!data.pr) {
    throw new Error('No invoice returned from LNURL')
  }

  return data.pr
}

/**
 * Parse the amount from a bolt11 invoice
 */
export function getInvoiceAmount(bolt11: string): number {
  return getSatoshisAmountFromBolt11(bolt11)
}


// ---------- NIP-57 integrity: the bolt11 description hash ----------

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26a08e26, 0x35ea6791, 0x1f0b1e0e, 0x0ee09feb]
  let chk = 1
  for (const v of values) {
    const b = chk >> 25
    chk = ((b & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]
  }
  return chk
}

function hrpExpand(hrp: string): number[] {
  return [...hrp].map(c => c.charCodeAt(0) >> 5).concat([0])
}

/**
 * The BOLT-11 `description` field of a zap invoice carries the SHA-256 of the
 * zap request (NIP-57). Returns that hash (hex), or null when the invoice is
 * not decodable or carries no description-hash field. Checksum and structure
 * are verified; synthetic invoices without the field return null.
 */
export function getInvoiceDescriptionHash(invoice: string): string | null {
  try {
    const lower = invoice.toLowerCase()
    const sep = lower.lastIndexOf('1')
    if (sep < 1) return null
    const hrp = lower.slice(0, sep)
    if (!hrp.startsWith('lnbc')) return null
    const values = [...lower.slice(sep + 1)].map(c => BECH32_CHARSET.indexOf(c))
    if (values.some(v => v < 0) || values.length < 116) return null
    if (bech32Polymod(hrpExpand(hrp).concat(values)) !== 1) return null
    const data = values.slice(0, -6)

    // 5-bit groups -> bytes (drops the padding bits of the last byte)
    let acc = 0, bits = 0
    const bytes: number[] = []
    for (const v of data) {
      acc = (acc << 5) | v; bits += 5
      while (bits >= 8) { bits -= 8; bytes.push((acc >> bits) & 0xff) }
    }

    // bytes: [7-byte timestamp][tagged fields...][104-byte signature]
    let i = 7
    while (bytes.length - i > 104) {
      const type = bytes[i]
      const len = (bytes[i + 1] << 8) | bytes[i + 2]
      if (i + 3 + len > bytes.length) return null
      if (type === 13 && len === 32) {
        return bytes.slice(i + 3, i + 3 + 32)
          .map(b => b.toString(16).padStart(2, '0')).join('')
      }
      i += 3 + len
    }
    return null
  } catch {
    return null
  }
}

// --- compact SHA-256 (FIPS 180-4) over UTF-8 bytes, sync (small inputs) ---
function rotr(x: number, n: number) { return (x >>> n) | (x << (32 - n)) }
function sha256Bytes(msg: Uint8Array): string {
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ]
  const H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
  const l = msg.length
  const padded = new Uint8Array(((l + 8) >> 6 << 6) + 64)
  padded.set(msg)
  padded[l] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, Math.floor(l / 0x20000000))
  dv.setUint32(padded.length - 4, (l << 3) >>> 0)
  const w = new Array<number>(64)
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4)
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const mj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + mj) | 0
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0
  }
  return H.map(x => (x >>> 0).toString(16).padStart(8, '0')).join('')
}

export function sha256Hex(input: string): string {
  return sha256Bytes(new TextEncoder().encode(input))
}

/**
 * Format sats for display (e.g., 21500 -> "21.5k")
 */
export function formatSats(sats: number): string {
  if (sats >= 1_000_000) {
    return `${(sats / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`
  }
  if (sats >= 1_000) {
    return `${(sats / 1_000).toFixed(1).replace(/\.0$/, '')}k`
  }
  return sats.toString()
}

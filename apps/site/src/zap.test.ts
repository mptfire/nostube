import { createHash } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getPublicKey, type NostrEvent } from 'nostr-tools'
import { describe, expect, it } from 'vitest'
import {
  checkInvoice,
  checkZapAmount,
  encodeLnurl,
  lnurlFromProfile,
  parseZapEndpoint,
  validZapReceipt,
  validZapReceipts,
  ZapError,
  type ZapTarget,
} from './zap'

const LNURL = 'https://pay.example/.well-known/lnurlp/creator'
const providerKey = generateSecretKey()
const senderKey = generateSecretKey()
const creator = getPublicKey(generateSecretKey())
const videoId = 'e'.repeat(64)
const address = `34235:${creator}:clip`

const endpoint = parseZapEndpoint(LNURL, {
  tag: 'payRequest',
  callback: 'https://pay.example/callback',
  minSendable: 1000,
  maxSendable: 10_000_000,
  allowsNostr: true,
  nostrPubkey: getPublicKey(providerKey),
  commentAllowed: 100,
})
const target: ZapTarget = { endpoint, recipient: creator, eventId: videoId, address }

/** A bolt11-shaped string whose human-readable part says 1000 sats (`10u`). */
const invoice1000 = (salt = 'q') => `lnbc10u1${salt.repeat(60)}`

function zapError(fn: () => unknown): string | undefined {
  try {
    fn()
  } catch (err) {
    return err instanceof ZapError ? err.code : 'other'
  }
}

function receipt({
  bolt11 = invoice1000(),
  signer = providerKey,
  e = videoId,
  profile = false,
} = {}): NostrEvent {
  // A profile zap names no event and no coordinate.
  const about = profile
    ? []
    : [
        ['e', e],
        ['a', address],
      ]
  const request = finalizeEvent(
    {
      kind: 9734,
      created_at: 1,
      content: '',
      tags: [
        ['p', creator],
        ...about,
        ['amount', '1000000'],
        ['lnurl', encodeLnurl(LNURL)],
        ['relays', 'wss://relay.example'],
      ],
    },
    senderKey
  )
  return finalizeEvent(
    {
      kind: 9735,
      created_at: 2,
      content: '',
      tags: [
        ['p', creator],
        ...about,
        ['bolt11', bolt11],
        ['description', JSON.stringify(request)],
      ],
    },
    signer
  )
}


/** A checksum-valid bolt11 for 1000 sats carrying a real description hash. */
function invoiceWithDescription(request: NostrEvent): string {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const sha256HexLocal = (input: string) => createHash('sha256').update(input).digest('hex')
  const descHash = sha256HexLocal(JSON.stringify(request))
  const hashBytes = (descHash.match(/../g) ?? []).map(h => parseInt(h, 16))
  const fields = [13, 0, 32, ...hashBytes]
  const ts = [0, 0, 0, 0, 0, 0, 1]
  const bytes = [...ts, ...fields, ...new Array(104).fill(0)]
  const data: number[] = []
  let acc = 0, bits = 0
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8
    while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31) }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31)
  const hrp = 'lnbc10u'
  const polymod = (values: number[]) => {
    const GEN = [0x3b6a57b2, 0x26a08e26, 0x35ea6791, 0x1f0b1e0e, 0x0ee09feb]
    let chk = 1
    for (const v of [...hrp.split('').map(c => c.charCodeAt(0) >> 5), 0, ...data, 0, 0, 0, 0, 0, 0]) {
      const b = chk >> 25
      chk = ((b & 0x1ffffff) << 5) ^ v
      for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]
    }
    return chk
  }
  const pm = polymod([]) ^ 1
  const checksum = [0, 1, 2, 3, 4, 5].map(i => (pm >> (5 * (5 - i))) & 31)
  return hrp + '1' + data.concat(checksum).map(v => CHARSET[v]).join('')
}

describe('lightning address', () => {
  it('resolves lud16 and lud06 to HTTPS LNURL-pay URLs only', () => {
    expect(lnurlFromProfile({ lud16: 'Creator@Pay.Example' })).toBe(LNURL)
    expect(lnurlFromProfile({ lud06: encodeLnurl(LNURL) })).toBe(LNURL)
    expect(lnurlFromProfile({ lud06: encodeLnurl('http://pay.example/x') })).toBeNull()
    expect(lnurlFromProfile({ lud16: 'not an address' })).toBeNull()
  })
})

describe('provider metadata', () => {
  const valid = {
    tag: 'payRequest',
    callback: 'https://pay.example/cb',
    minSendable: 1000,
    maxSendable: 2_000_000,
    allowsNostr: true,
    nostrPubkey: 'a'.repeat(64),
  }

  it('rejects providers that cannot take a whole-sat payment or a verifiable zap', () => {
    // No zaps: still a plain LNURL payment, whose receipts never count as zaps.
    const plain = parseZapEndpoint(LNURL, { ...valid, allowsNostr: false })
    expect(plain.nostrPubkey).toBeUndefined()
    expect(validZapReceipt(receipt(), { ...target, endpoint: plain })).toBeNull()
    for (const bad of [
      { callback: 'http://pay.example/cb' },
      { nostrPubkey: 'zz' },
      { minSendable: 1500, maxSendable: 1999 },
      { maxSendable: 0 },
      { minSendable: '1000' },
    ]) {
      expect(zapError(() => parseZapEndpoint(LNURL, { ...valid, ...bad }))).toBe('providerInvalid')
    }
    expect(zapError(() => parseZapEndpoint(LNURL, { status: 'ERROR', reason: 'x' }))).toBe(
      'providerFailed'
    )
  })

  it('only accepts safe whole amounts inside the sendable range', () => {
    expect(endpoint).toMatchObject({ minSats: 1, maxSats: 10_000, commentAllowed: 100 })
    for (const sats of [0, -1, 1.5, Number.NaN, 10_001]) {
      expect(zapError(() => checkZapAmount(sats, endpoint))).toBe('invalidAmount')
    }
    expect(zapError(() => checkZapAmount(1000, endpoint))).toBeUndefined()
  })
})

describe('invoice', () => {
  it('accepts only a mainnet invoice for exactly the requested amount', () => {
    expect(checkInvoice(invoice1000(), 1000)).toBe(invoice1000())
    expect(zapError(() => checkInvoice(invoice1000(), 999))).toBe('invoiceMismatch')
    expect(zapError(() => checkInvoice(`lntb10u1${'q'.repeat(60)}`, 1000))).toBe('invoiceMismatch')
    expect(zapError(() => checkInvoice(undefined, 1000))).toBe('invoiceMismatch')
  })
})

describe('zap receipts', () => {
  it('counts a provider-signed receipt for this video once per invoice', () => {
    const valid = receipt()
    expect(validZapReceipt(valid, target)?.sats).toBe(1000)
    // An older version of an addressable video still matches by coordinate.
    expect(validZapReceipt(receipt({ e: 'f'.repeat(64) }), target)?.sats).toBe(1000)
    const total = validZapReceipts([valid, valid, receipt({ bolt11: invoice1000('r') })], target)
    expect(total.reduce((sum, r) => sum + r.sats, 0)).toBe(2000)
  })

  it('rejects fake, mismatched or foreign receipts', () => {
    const genuine = receipt()
    // JSON round trip drops nostr-tools' cached "verified" flag, like an event off the wire.
    const swappedInvoice: NostrEvent = JSON.parse(JSON.stringify(genuine))
    swappedInvoice.tags = genuine.tags.map(t =>
      t[0] === 'bolt11' ? ['bolt11', invoice1000('z')] : t
    )
    // Signed by someone other than the creator's provider.
    expect(validZapReceipt(receipt({ signer: generateSecretKey() }), target)).toBeNull()
    // Provider signature no longer covers the tags.
    expect(validZapReceipt(swappedInvoice, target)).toBeNull()
    // Invoice for 2000 sats, signed request for 1000.
    expect(validZapReceipt(receipt({ bolt11: `lnbc20u1${'q'.repeat(60)}` }), target)).toBeNull()
    // Zero-amount invoice.
    expect(validZapReceipt(receipt({ bolt11: `lnbc1${'q'.repeat(60)}` }), target)).toBeNull()
    // Another event, and no coordinate to match.
    expect(
      validZapReceipt(receipt({ e: 'f'.repeat(64) }), { ...target, address: undefined })
    ).toBeNull()
    // Someone else's zap.
    expect(validZapReceipt(genuine, { ...target, recipient: 'b'.repeat(64) })).toBeNull()
    const otherLnurl = parseZapEndpoint('https://other.example/lnurlp/x', {
      tag: 'payRequest',
      callback: 'https://other.example/cb',
      minSendable: 1000,
      maxSendable: 10_000_000,
      allowsNostr: true,
      nostrPubkey: endpoint.nostrPubkey,
    })
    expect(validZapReceipt(receipt(), { ...target, endpoint: otherLnurl })).toBeNull()
  })

  it('binds the zap request to the invoice description hash (NIP-57)', async () => {
    const { sha256Hex, getInvoiceDescriptionHash } = await import('@nostube/core/zap-utils')
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    const zapRequest = (content: string) =>
      finalizeEvent(
        {
          kind: 9734,
          created_at: 1,
          content,
          tags: [
            ['p', creator],
            ['e', videoId],
            ['a', address],
            ['amount', '1000000'],
            ['lnurl', encodeLnurl(LNURL)],
            ['relays', 'wss://relay.example'],
          ],
        },
        senderKey
      )

    // A consistent pair: the wallet's invoice embeds sha256 of the request.
    const request = zapRequest('')
    const invoice = invoiceWithDescription(request)
    const good = finalizeEvent(
      {
        kind: 9735,
        created_at: 2,
        content: '',
        tags: [
          ['p', creator],
          ['e', videoId],
          ['a', address],
          ['bolt11', invoice],
          ['description', JSON.stringify(request)],
        ],
      },
      providerKey
    )
    expect(validZapReceipt(good, target)?.sats).toBe(1000)

    // A malicious provider signs an invoice/hash pair that does not cover the
    // request it claims: the description binding must reject it.
    const otherRequest = zapRequest('tampered')
    const otherInvoice = invoiceWithDescription(otherRequest)
    const mismatched = finalizeEvent(
      {
        kind: 9735,
        created_at: 2,
        content: '',
        tags: [
          ['p', creator],
          ['e', videoId],
          ['a', address],
          ['bolt11', otherInvoice],
          ['description', JSON.stringify(request)], // request of the OTHER pair
        ],
      },
      providerKey
    )
    expect(validZapReceipt(mismatched, target)).toBeNull()
  })

  it('counts only zaps of the profile itself for a profile target', () => {
    const profileTarget: ZapTarget = { endpoint, recipient: creator }
    expect(validZapReceipt(receipt({ profile: true }), profileTarget)?.sats).toBe(1000)
    // A zap of a video is not a zap of the profile, and vice versa.
    expect(validZapReceipt(receipt(), profileTarget)).toBeNull()
    expect(validZapReceipt(receipt({ profile: true }), target)).toBeNull()
  })
})

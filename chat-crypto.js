// Criptografia do chat, em três camadas. Só usa primitivas prontas do Web Crypto (AES-GCM, ECDSA,
// ECDH, HKDF, HMAC); o que este arquivo decide é como combiná-las. Feito para estudo, não auditado.
//
// 1. Chave da sala (AES-GCM): vem no convite, depois do "#". Sem ela não se lê nem se altera nada:
//    nem a sinalização no broker, nem o que circula pela mesh.
// 2. Identidade (ECDSA P-256): cada pessoa assina o que escreve. A impressão digital da chave pública
//    é o que vocês comparam por outro canal para saber que ninguém se passa por ninguém.
// 3. Sender keys com catraca (HMAC): cada pessoa cifra as próprias mensagens com uma corrente de
//    chaves que só anda para frente e entrega a corrente atual a cada membro, cifrada só para ele (ECDH).
//    Chave usada é descartada: quem chega depois e quem vaza a chave de hoje não leem o passado.
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const MAX_SKIP = 100 // quantas mensagens fora de ordem eu aceito guardar a chave

export const toBase64 = bytes =>
  btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
export const fromBase64 = text => Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), char => char.charCodeAt(0))

// ---------- 1. chave da sala ----------

export const newRoomSecret = () => toBase64(crypto.getRandomValues(new Uint8Array(32)))
export const importRoomKey = secret => crypto.subtle.importKey('raw', fromBase64(secret), 'AES-GCM', false, ['encrypt', 'decrypt'])

export async function seal(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(value)))
  return { iv: toBase64(iv), ct: toBase64(ciphertext) }
}

// undefined = chave errada ou conteúdo adulterado: o GCM detecta os dois.
export async function unseal(key, { iv, ct }) {
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(iv) }, key, fromBase64(ct))
    return JSON.parse(decoder.decode(plaintext))
  } catch {
    return undefined
  }
}

// ---------- 2. identidade ----------

const SIGNING = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGNATURE = { name: 'ECDSA', hash: 'SHA-256' }
const signable = parts => encoder.encode(JSON.stringify(parts))

export const newIdentity = () => crypto.subtle.generateKey(SIGNING, false, ['sign', 'verify'])
export const exportPublicKey = async key => toBase64(await crypto.subtle.exportKey('raw', key))
export const sign = async (privateKey, parts) => toBase64(await crypto.subtle.sign(SIGNATURE, privateKey, signable(parts)))

export async function verify(publicKey, parts, signature) {
  try {
    const key = await crypto.subtle.importKey('raw', fromBase64(publicKey), SIGNING, false, ['verify'])
    return await crypto.subtle.verify(SIGNATURE, key, fromBase64(signature), signable(parts))
  } catch {
    return false
  }
}

// 80 bits do SHA-256 da chave pública, em 5 grupos: "3f2a 91c0 7b44 0e1d 55aa".
export async function fingerprintOf(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', fromBase64(publicKey)))
  const hex = [...digest.slice(0, 10)].map(byte => byte.toString(16).padStart(2, '0')).join('')
  return hex.match(/.{4}/g).join(' ')
}

// ---------- 3. chaves de sessão e catraca ----------

const AGREEMENT = { name: 'ECDH', namedCurve: 'P-256' }

// Gerado a cada vez que a página abre e nunca guardado: fechou a página, a chave some.
export const newSessionKeys = () => crypto.subtle.generateKey(AGREEMENT, false, ['deriveBits'])

// Os dois lados chegam à mesma chave: ECDH(meu privado, público dele) = ECDH(privado dele, meu público).
export async function pairwiseKey(myPrivateKey, theirPublicKey) {
  const theirs = await crypto.subtle.importKey('raw', fromBase64(theirPublicKey), AGREEMENT, false, [])
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, myPrivateKey, 256)
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const params = { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode('mesh-lab sender-key') }
  return crypto.subtle.deriveKey(params, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

export const newChain = () => ({ chain: crypto.getRandomValues(new Uint8Array(32)), n: 0, skipped: new Map() })
export const exportChain = state => ({ chain: toBase64(state.chain), n: state.n })

export function importChain(value) {
  if (typeof value?.chain !== 'string' || !Number.isInteger(value.n) || value.n < 0) return undefined
  const chain = fromBase64(value.chain)
  return chain.length === 32 ? { chain, n: value.n, skipped: new Map() } : undefined
}

// Um passo da catraca: da chave de corrente saem a chave desta mensagem e a próxima chave de corrente.
// HMAC não volta atrás: quem tem a corrente de agora não chega às anteriores.
async function step(chain) {
  const key = await crypto.subtle.importKey('raw', chain, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const derive = async label => new Uint8Array(await crypto.subtle.sign('HMAC', key, new Uint8Array([label])))
  return { messageKey: await derive(1), nextChain: await derive(2) }
}

const messageKeyFor = bytes => crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt'])

// Operações na mesma corrente rodam uma de cada vez, senão duas mensagens usariam o mesmo número.
function serialize(state, task) {
  const run = (state.lock ?? Promise.resolve()).then(task)
  state.lock = run.catch(() => {})
  return run
}

// build(n) monta o conteúdo já sabendo o número da mensagem (para a assinatura cobrir o número).
export function ratchetSeal(state, build) {
  return serialize(state, async () => {
    const n = state.n
    const { messageKey, nextChain } = await step(state.chain)
    state.chain = nextChain // a corrente anterior deixa de existir aqui
    state.n = n + 1
    return { n, ...(await seal(await messageKeyFor(messageKey), await build(n))) }
  })
}

export function ratchetUnseal(state, { n, iv, ct }) {
  return serialize(state, async () => {
    if (!Number.isInteger(n) || n < 0) return undefined
    const skippedKey = state.skipped.get(n)
    if (skippedKey) {
      const value = await unseal(await messageKeyFor(skippedKey), { iv, ct })
      if (value !== undefined) state.skipped.delete(n)
      return value
    }
    // Número já usado (repetição) ou longe demais no futuro.
    if (n < state.n || n - state.n > MAX_SKIP) return undefined

    // Avanço numa cópia e só confirmo se decifrar: um pacote forjado não estraga a corrente.
    let chain = state.chain
    const skipped = new Map()
    for (let index = state.n; index < n; index++) {
      const next = await step(chain)
      skipped.set(index, next.messageKey) // mensagem que ainda não chegou: guardo a chave dela
      chain = next.nextChain
    }
    const { messageKey, nextChain } = await step(chain)
    const value = await unseal(await messageKeyFor(messageKey), { iv, ct })
    if (value === undefined) return undefined
    for (const [index, key] of skipped) state.skipped.set(index, key)
    while (state.skipped.size > MAX_SKIP) state.skipped.delete(state.skipped.keys().next().value)
    state.chain = nextChain
    state.n = n + 1
    return value
  })
}

// Usage : node verify.mjs vc.json   -> affiche {"verified":true|false,...} ; code retour 0 si vérifié
// Les contextes W3C sont pris dans les paquets npm officiels ; le contexte métier et le DID
// sont récupérés en HTTP auprès de l'issuer (résolution did:web réelle).
import fs from 'fs';
import * as vc from '@digitalbazaar/vc';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import cred from 'credentials-context';
import ed from 'ed25519-signature-2020-context';
import didctx from 'did-context';

const local = new Map([...cred.contexts, ...ed.contexts, ...didctx.contexts]);

function didWebToUrl(did) {
  const parts = did.split(':').slice(2).map(decodeURIComponent);
  const host = parts.shift();
  // did:web impose HTTPS ; localhost est résolu en HTTP pour les tests
  const scheme = /^(localhost|127\.0\.0\.1)(:|$)/.test(host) ? 'http' : 'https';
  return `${scheme}://${host}/${parts.length ? parts.join('/') : '.well-known'}/did.json`;
}

async function documentLoader(url) {
  if (local.has(url)) return {document: local.get(url), documentUrl: url};
  if (url.startsWith('did:web:')) {
    const [did, frag] = url.split('#');
    const doc = await (await fetch(didWebToUrl(did))).json();
    if (doc.id !== did) throw new Error(`DID document id ${doc.id} != ${did}`);
    if (!frag) return {document: doc, documentUrl: url};
    const vm = doc.verificationMethod.find(m => m.id === url);
    if (!vm) throw new Error('verificationMethod introuvable : ' + url);
    return {document: {'@context': 'https://w3id.org/security/suites/ed25519-2020/v1', ...vm}, documentUrl: url};
  }
  if (/^https?:\/\/.*\/contexts\/sn-national-id-v1\.jsonld$/.test(url)) {
    return {document: await (await fetch(url)).json(), documentUrl: url};
  }
  throw new Error('URL non autorisée : ' + url);
}

const credential = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const r = await vc.verifyCredential({credential, suite: new Ed25519Signature2020(), documentLoader});
const err = r.error ? (r.error.errors || [r.error]).map(e => e.message).join(' | ') : undefined;
console.log(JSON.stringify({verified: r.verified, error: err}));
process.exit(r.verified ? 0 : 1);

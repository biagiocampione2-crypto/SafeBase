'use strict';

const APP_VERSION = '5.6.5';
const DISPLAY_VERSION = APP_VERSION;
const CRYPTO_SCHEMA_VERSION = 3;
const DB_NAME = 'SafeBaseDB';
const DB_VERSION = 2;
const META_KEY = 'vaultMeta';
const PBKDF2_ITERATIONS = 650000;
const PIN_LENGTH = 6;
const AUTH_MODE_PIN6 = 'pin6';
const PIN_MAX_FAILURES = 5;
const PIN_LOCKOUT_MS = 30000;
const PIN_FAILURE_STATE_KEY = 'safebase:pin-failure-state:v1';
const MIN_ACCEPTED_ITERATIONS = 100000;
const MAX_ACCEPTED_ITERATIONS = 1500000;
const CLIPBOARD_CLEAR_MS = 30000;
const TOTP_PERIOD_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_SECRET_BYTES = 20;
const TOTP_ALLOWED_DRIFT_STEPS = 1;
const TOTP_MAX_FAILURES = 5;
const TOTP_LOCKOUT_MS = 30000;
const RECOVERY_CODE_COUNT = 10;
const TWO_FACTOR_PENDING_TTL_MS = 2 * 60 * 1000;
const TWO_FACTOR_SETUP_TTL_MS = 3 * 60 * 1000;
const EXTERNAL_VAULT_VERSION = 3;
const EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION = 2;
const EXTERNAL_VAULT_LEGACY_VERSION = 1;
const EXTERNAL_VAULT_ITERATIONS = 650000;
const EXTERNAL_FILE_MAX_BYTES = 100 * 1024 * 1024;
const EXTERNAL_VAULT_MAX_BYTES = 300 * 1024 * 1024;
const EXTERNAL_DRAFT_KEY = 'externalVaultDraftV1';
const EXTERNAL_MAGIC = new Uint8Array([0x53,0x42,0x56,0x35]); // SBV5
const EXTERNAL_MANIFEST_AAD_V1 = 'safebase:external-manifest:v5';
const EXTERNAL_MANIFEST_AAD_V2 = 'safebase:external-manifest:v5.1:passkey';
const EXTERNAL_MANIFEST_AAD_V3 = 'safebase:external-manifest:v5.2:passkey-only';
const externalManifestAAD = version => version===EXTERNAL_VAULT_LEGACY_VERSION ? EXTERNAL_MANIFEST_AAD_V1 : version===EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION ? EXTERNAL_MANIFEST_AAD_V2 : EXTERNAL_MANIFEST_AAD_V3;
const externalFileAAD = (id,version=EXTERNAL_VAULT_VERSION) => version===EXTERNAL_VAULT_LEGACY_VERSION ? `safebase:external-file:${id}:v5` : version===EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION ? `safebase:external-file:${id}:v5.1:passkey` : `safebase:external-file:${id}:v5.2:passkey-only`;
const EXTERNAL_V3_HKDF_INFO = 'SafeBase External Vault v3 / WebAuthn-PRF only';
const BACKUP_VERSION = 1;
const BACKUP_MAX_BYTES = 16 * 1024 * 1024;
const BACKUP_MAGIC = new Uint8Array([0x53,0x42,0x42,0x31]); // SBB1
const BACKUP_HKDF_INFO = 'SafeBase Backup v1 / WebAuthn-PRF only';
const BACKUP_AAD = 'safebase:backup:v1:passkey-only';
const enc = new TextEncoder();
const dec = new TextDecoder();

let db;
let sessionKey = null;
let sessionVault = null;
let pendingSessionKey = null;
let pendingSessionVault = null;
let pendingTwoFactorSecret = null;
let pendingRecoveryCodes = null;
let twoFactorFailures = 0;
let twoFactorBlockedUntil = 0;
let pinFailures = 0;
let pinBlockedUntil = 0;
let pendingTwoFactorTimer = null;
let pendingTwoFactorExpiresAt = 0;
let twoFactorSetupActive = false;
let twoFactorSetupTimer = null;
let autoLockTimer = null;
let lastActivity = Date.now();
let clipboardTimer = null;
let systemPickerActive = false;
let filePickerAwaitingId = null;
let filePickerRecoveryTimer = null;
let passwordRevealTimer = null;
let sessionEpoch = 0;
let externalVault = null;
let externalVaultPasswordMode = null;
let pendingExternalOpenFile = null;
let pendingExternalOpenHeader = null;
let externalPreviewUrl = null;
let externalSaveHandle = null;
let externalListFilter = 'all';
let externalListSort = 'newest';
let externalActionItemId = null;
let externalVaultNameResolver = null;
let backupCredentialResolver = null;
let backupCredentialPinMode = false;
let backupPasskeyNameResolver = null;
let backupRestorePinResolver = null;
let pendingPasskeyBackupFile = null;
let pendingPasskeyBackupLabel = '';
let externalDraftRevision = 0;
let externalDraftSavedRevision = -1;
let externalDraftSavePromise = null;
let externalDraftWarningShown = false;

const $ = id => document.getElementById(id);
const setupView = $('setupView');
const unlockView = $('unlockView');
const pinMigrationView = $('pinMigrationView');
const vaultView = $('vaultView');
const statusText = $('statusText');
const lockBtn = $('lockBtn');

const AAD = {
  wrappedKey: 'safebase:wrapped-key:v3',
  verifier: 'safebase:verifier:v3',
  vault: 'safebase:vault:v3'
};

function b64(bytes){
  const CHUNK = 0x8000;
  let binary = '';
  for(let i=0;i<bytes.length;i+=CHUNK){
    binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i+CHUNK, bytes.length)));
  }
  return btoa(binary);
}
function unb64(str){
  if(typeof str !== 'string' || !str.length) throw new Error('Ungültige Base64-Daten');
  const binary = atob(str);
  const out = new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) out[i]=binary.charCodeAt(i);
  return out;
}
function randomBytes(n){ const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function uuid(){ return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${b64(randomBytes(12)).replace(/[^a-z0-9]/gi,'')}`; }
function nowISO(){ return new Date().toISOString(); }
function safeText(v=''){ return String(v ?? ''); }
function normalizePin(value){ return String(value ?? '').replace(/\D/g,'').slice(0,PIN_LENGTH); }
function isValidPin(value){ return /^\d{6}$/.test(String(value ?? '')); }
function isPinMeta(meta){ return meta?.authMode === AUTH_MODE_PIN6; }
function loadPinFailureState(){
  try{
    const state=JSON.parse(localStorage.getItem(PIN_FAILURE_STATE_KEY)||'null');
    pinFailures=Number.isInteger(state?.failures)?Math.max(0,Math.min(PIN_MAX_FAILURES-1,state.failures)):0;
    pinBlockedUntil=Number.isFinite(Number(state?.blockedUntil))?Math.max(0,Number(state.blockedUntil)):0;
    if(pinBlockedUntil && Date.now()>=pinBlockedUntil) clearPinFailures();
  }catch{ pinFailures=0; pinBlockedUntil=0; }
}
function persistPinFailureState(){
  try{ localStorage.setItem(PIN_FAILURE_STATE_KEY,JSON.stringify({failures:pinFailures,blockedUntil:pinBlockedUntil})); }catch{}
}
function registerPinFailure(){
  pinFailures += 1;
  if(pinFailures >= PIN_MAX_FAILURES){
    pinBlockedUntil = Date.now() + PIN_LOCKOUT_MS;
    pinFailures = 0;
  }
  persistPinFailureState();
}
function clearPinFailures(){
  pinFailures=0; pinBlockedUntil=0;
  try{ localStorage.removeItem(PIN_FAILURE_STATE_KEY); }catch{}
}
function wipe(bytes){ try{ if(bytes?.fill) bytes.fill(0); }catch{} }
function isV3Meta(meta){ return Number(meta?.schemaVersion || meta?.version || 0) >= 3 && !!meta?.wrappedKey; }
async function openDB(){
  return new Promise((resolve,reject)=>{
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const d = req.result;
      if(!d.objectStoreNames.contains('meta')) d.createObjectStore('meta');
      if(!d.objectStoreNames.contains('files')) d.createObjectStore('files', {keyPath:'id'});
      if(!d.objectStoreNames.contains('stagingFiles')) d.createObjectStore('stagingFiles', {keyPath:'id'});
    };
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}
function tx(store,mode='readonly'){ return db.transaction(store,mode).objectStore(store); }
function idbGet(store,key){ return new Promise((res,rej)=>{ const r=tx(store).get(key); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
function idbPut(store,val,key){ return new Promise((res,rej)=>{ const r=key===undefined?tx(store,'readwrite').put(val):tx(store,'readwrite').put(val,key); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
function idbDelete(store,key){ return new Promise((res,rej)=>{ const r=tx(store,'readwrite').delete(key); r.onsuccess=()=>res(); r.onerror=()=>rej(r.error); }); }
function idbGetAll(store){ return new Promise((res,rej)=>{ const r=tx(store).getAll(); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
function idbGetAllKeys(store){ return new Promise((res,rej)=>{ const r=tx(store).getAllKeys(); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
function idbClear(store){ return new Promise((res,rej)=>{ const r=tx(store,'readwrite').clear(); r.onsuccess=()=>res(); r.onerror=()=>rej(r.error); }); }

function atomicReplace(metaRecord, fileRecords){
  return new Promise((resolve,reject)=>{
    const t=db.transaction(['meta','files'],'readwrite');
    const m=t.objectStore('meta');
    const f=t.objectStore('files');
    m.clear(); f.clear();
    m.put(metaRecord,META_KEY);
    for(const record of fileRecords) f.put(record);
    t.oncomplete=()=>resolve();
    t.onerror=()=>reject(t.error || new Error('Speichertransaktion fehlgeschlagen'));
    t.onabort=()=>reject(t.error || new Error('Speichertransaktion abgebrochen'));
  });
}

function commitStaging(metaRecord){
  return new Promise((resolve,reject)=>{
    const t=db.transaction(['meta','files','stagingFiles'],'readwrite');
    const m=t.objectStore('meta');
    const f=t.objectStore('files');
    const s=t.objectStore('stagingFiles');
    f.clear();
    const cursorReq=s.openCursor();
    cursorReq.onsuccess=()=>{
      const cursor=cursorReq.result;
      if(cursor){ f.put(cursor.value); cursor.continue(); }
      else { m.clear(); m.put(metaRecord,META_KEY); s.clear(); }
    };
    t.oncomplete=()=>resolve();
    t.onerror=()=>reject(t.error || new Error('Migration fehlgeschlagen'));
    t.onabort=()=>reject(t.error || new Error('Migration abgebrochen'));
  });
}

function kdfParams(meta){
  const saltText = meta?.kdf?.salt || meta?.salt;
  const iterations = Number(meta?.kdf?.iterations || meta?.iterations || 0);
  if(!saltText) throw new Error('KDF-Salt fehlt');
  if(!Number.isInteger(iterations) || iterations < MIN_ACCEPTED_ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS){
    throw new Error('Ungültige KDF-Parameter');
  }
  const salt=unb64(saltText);
  if(salt.length < 16 || salt.length > 64) throw new Error('Ungültiger KDF-Salt');
  return {salt,iterations};
}

async function deriveKey(password,salt,iterations=PBKDF2_ITERATIONS){
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations,hash:'SHA-256'},
    material,
    {name:'AES-GCM',length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function importDataKey(raw){
  if(!(raw instanceof Uint8Array) || raw.length!==32) throw new Error('Ungültiger Tresorschlüssel');
  return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
}
function encryptedFieldBytes(value){
  if(typeof value==='string') return unb64(value);
  if(value instanceof Uint8Array) return value;
  if(value instanceof ArrayBuffer) return new Uint8Array(value);
  if(ArrayBuffer.isView(value)) return new Uint8Array(value.buffer,value.byteOffset,value.byteLength);
  throw new Error('Ungültiges verschlüsseltes Binärformat');
}
function encryptedFieldB64(value){ return typeof value==='string' ? value : b64(encryptedFieldBytes(value)); }
async function encryptBytes(bytes,key,aad=''){
  const iv=randomBytes(12);
  const params={name:'AES-GCM',iv,tagLength:128};
  if(aad) params.additionalData=enc.encode(aad);
  const ct=await crypto.subtle.encrypt(params,key,bytes);
  return {iv:b64(iv),data:b64(new Uint8Array(ct))};
}
// Large file payloads stay binary inside IndexedDB. This avoids Base64 expansion
// and substantially reduces the local storage required for photos/videos.
async function encryptBytesBinary(bytes,key,aad=''){
  const iv=randomBytes(12);
  const params={name:'AES-GCM',iv,tagLength:128};
  if(aad) params.additionalData=enc.encode(aad);
  const ct=await crypto.subtle.encrypt(params,key,bytes);
  return {iv, data:new Uint8Array(ct)};
}
async function decryptBytes(payload,key,aad=''){
  if(!payload?.iv || !payload?.data) throw new Error('Verschlüsselte Daten fehlen');
  const iv=encryptedFieldBytes(payload.iv);
  if(iv.length!==12) throw new Error('Ungültiger IV');
  const params={name:'AES-GCM',iv,tagLength:128};
  if(aad) params.additionalData=enc.encode(aad);
  const pt=await crypto.subtle.decrypt(params,key,encryptedFieldBytes(payload.data));
  return new Uint8Array(pt);
}
async function encryptJSON(value,key,aad=''){ return encryptBytes(enc.encode(JSON.stringify(value)),key,aad); }
async function decryptJSON(payload,key,aad=''){ return JSON.parse(dec.decode(await decryptBytes(payload,key,aad))); }

function defaultVault(){ return {version:APP_VERSION,passwords:[],notes:[],settings:{autoLockMinutes:5,twoFactor:{enabled:false}},updatedAt:nowISO()}; }

async function createV3Meta(credential,dataKeyRaw,dataKey,vault,authMode=AUTH_MODE_PIN6){
  const salt=randomBytes(32);
  const kek=await deriveKey(credential,salt,PBKDF2_ITERATIONS);
  const wrappedKey=await encryptBytes(dataKeyRaw,kek,AAD.wrappedKey);
  const verifier=await encryptJSON({ok:true,version:APP_VERSION},dataKey,AAD.verifier);
  const encryptedVault=await encryptJSON(vault,dataKey,AAD.vault);
  return {
    version:APP_VERSION,
    schemaVersion:CRYPTO_SCHEMA_VERSION,
    authMode,
    salt:b64(salt),
    iterations:PBKDF2_ITERATIONS,
    kdf:{name:'PBKDF2',hash:'SHA-256',iterations:PBKDF2_ITERATIONS,salt:b64(salt)},
    wrappedKey,
    verifier,
    vault:encryptedVault
  };
}

async function unwrapV3DataKey(meta,password){
  const {salt,iterations}=kdfParams(meta);
  const kek=await deriveKey(password,salt,iterations);
  const raw=await decryptBytes(meta.wrappedKey,kek,AAD.wrappedKey);
  try{
    const dataKey=await importDataKey(raw);
    const check=await decryptJSON(meta.verifier,dataKey,AAD.verifier);
    if(!check?.ok) throw new Error('Verifikation fehlgeschlagen');
    return {dataKey,rawKey:raw,kekIterations:iterations};
  }catch(e){ wipe(raw); throw e; }
}

async function saveVault(){
  if(!sessionKey||!sessionVault) throw new Error('Tresor ist gesperrt');
  sessionVault.updatedAt=nowISO();
  const encrypted=await encryptJSON(sessionVault,sessionKey,AAD.vault);
  const meta=await idbGet('meta',META_KEY);
  if(!isV3Meta(meta)) throw new Error('Tresorformat muss aktualisiert werden');
  meta.vault=encrypted;
  await idbPut('meta',meta,META_KEY);
  renderAll();
}

async function setupVault(pin){
  const raw=randomBytes(32);
  try{
    const key=await importDataKey(raw);
    const vault=defaultVault();
    const meta=await createV3Meta(pin,raw,key,vault,AUTH_MODE_PIN6);
    await atomicReplace(meta,[]);
    sessionKey=key; sessionVault=vault;
    await requestPersistentStorage();
    showVault();
  } finally { wipe(raw); }
}

async function migrateLegacyToV3(password,legacyMeta,legacyKey,legacyVault){
  const raw=randomBytes(32);
  try{
    const dataKey=await importDataKey(raw);
    const meta=await createV3Meta(password,raw,dataKey,{...legacyVault,version:APP_VERSION},'legacy-password');
    await atomicReplace(meta,[]);
    await idbClear('stagingFiles');
    return {dataKey,meta};
  } finally { wipe(raw); }
}

async function upgradeV3KdfIfNeeded(password,meta,rawKey){
  const current=Number(meta?.kdf?.iterations || meta?.iterations || 0);
  if(current>=PBKDF2_ITERATIONS) return meta;
  const salt=randomBytes(32);
  const kek=await deriveKey(password,salt,PBKDF2_ITERATIONS);
  const updated={...meta,
    version:APP_VERSION,schemaVersion:CRYPTO_SCHEMA_VERSION,authMode:meta.authMode || 'legacy-password',
    salt:b64(salt),iterations:PBKDF2_ITERATIONS,
    kdf:{name:'PBKDF2',hash:'SHA-256',iterations:PBKDF2_ITERATIONS,salt:b64(salt)},
    wrappedKey:await encryptBytes(rawKey,kek,AAD.wrappedKey)
  };
  await idbPut('meta',updated,META_KEY);
  return updated;
}

async function unlockVault(password){
  const meta=await idbGet('meta',META_KEY);
  if(!meta) throw new Error('Kein Tresor vorhanden');
  if(isV3Meta(meta)){
    const unlocked=await unwrapV3DataKey(meta,password);
    try{
      const vault=await decryptJSON(meta.vault,unlocked.dataKey,AAD.vault);
      await upgradeV3KdfIfNeeded(password,meta,unlocked.rawKey);
      const upgradedVault={...vault,version:APP_VERSION};
      if(isTwoFactorEnabled(upgradedVault)){
        beginSecondFactor(unlocked.dataKey,upgradedVault);
      }else{
        sessionKey=unlocked.dataKey; sessionVault=upgradedVault; showVault();
      }
    } finally { wipe(unlocked.rawKey); }
    return;
  }

  // V1/V2 compatibility: decrypt with the old password-derived key, then migrate once.
  const {salt,iterations}=kdfParams(meta);
  const legacyKey=await deriveKey(password,salt,iterations);
  const check=await decryptJSON(meta.verifier,legacyKey);
  if(!check?.ok) throw new Error('Ungültiges Passwort');
  const legacyVault=await decryptJSON(meta.vault,legacyKey);
  const migrated=await migrateLegacyToV3(password,meta,legacyKey,legacyVault);
  sessionKey=migrated.dataKey; sessionVault={...legacyVault,version:APP_VERSION,settings:{autoLockMinutes:Number(legacyVault.settings?.autoLockMinutes||5),twoFactor:{enabled:false}}};
  showVault();
  toast('Sicherheitsupgrade auf SafeBase v5 abgeschlossen');
}

function clearSensitiveUI(){
  closeExternalPreview();
  clearExternalVault(false);
  clearTimeout(passwordRevealTimer); passwordRevealTimer=null;
  ['passwordList','noteList'].forEach(id=>{ const el=$(id); if(el) el.textContent=''; });
  ['searchPasswords','searchNotes','searchExternalFiles','externalRenameInput','entryName','entryUsername','entryPassword','entryWebsite','entryNote','noteTitle','noteBody','currentPassword','newPassword','newPassword2','generatedPassword','twoFactorCode','twoFactorRecoveryCode','twoFactorSetupPassword','twoFactorSetupCode','twoFactorManagePassword','twoFactorManageCode','recoveryCodesText','externalVaultPassword','externalVaultPasswordConfirm','backupCredentialInput','backupPasskeyNameInput','backupRestorePin','backupRestorePin2','legacyMasterPassword','legacyNewPin','legacyNewPin2'].forEach(id=>{ const el=$(id); if(el) el.value=''; });
  ['passwordDialog','noteDialog','changePasswordDialog','twoFactorSetupDialog','twoFactorManageDialog','recoveryCodesDialog','externalVaultPasswordDialog','externalItemMenuDialog','externalRenameDialog','externalInfoDialog','backupCredentialDialog','backupPasskeyNameDialog','backupSaveDialog','backupRestorePinDialog'].forEach(id=>{ const d=$(id); if(d?.open) d.close(); });
  $('pwCount').textContent='0'; $('noteCount').textContent='0'; const ef=$('externalFileCount'); if(ef) ef.textContent='0';
}
function lockVault(){
  sessionEpoch++;
  clearPendingSession();
  clearSensitiveUI();
  sessionKey=null; sessionVault=null;
  pendingPasskeyBackupFile=null; pendingPasskeyBackupLabel=''; updateBackupRetryButton(false);
  clearTimeout(autoLockTimer);
  vaultView.classList.add('hidden'); $('twoFactorView')?.classList.add('hidden'); pinMigrationView?.classList.add('hidden'); unlockView.classList.remove('hidden'); setupView.classList.add('hidden');
  lockBtn.classList.add('hidden'); statusText.textContent='Gesperrt'; $('unlockPassword').value='';
}
function showVault(){
  sessionEpoch++;
  setupView.classList.add('hidden'); pinMigrationView?.classList.add('hidden'); unlockView.classList.add('hidden'); $('twoFactorView')?.classList.add('hidden'); vaultView.classList.remove('hidden'); lockBtn.classList.remove('hidden'); statusText.textContent=`Entsperrt • lokal • v${DISPLAY_VERSION}`;
  renderAll(); resetAutoLock();
}
function toast(msg){ const t=$('toast'); t.textContent=msg; t.classList.remove('hidden'); setTimeout(()=>t.classList.add('hidden'),2400); }

function beginFilePicker(id){
  filePickerAwaitingId=id;
  clearTimeout(filePickerRecoveryTimer);
  systemPickerActive=true;
  clearTimeout(autoLockTimer);
}
function filePickerSelectionStarted(id){
  if(filePickerAwaitingId===id) filePickerAwaitingId=null;
}
function endFilePicker(){
  clearTimeout(filePickerRecoveryTimer);
  filePickerAwaitingId=null;
  systemPickerActive=false;
  if(sessionVault) resetAutoLock();
}
function recoverCanceledFilePicker(){
  if(!filePickerAwaitingId) return;
  const expected=filePickerAwaitingId;
  clearTimeout(filePickerRecoveryTimer);
  filePickerRecoveryTimer=setTimeout(()=>{
    if(filePickerAwaitingId===expected) endFilePicker();
  },450);
}
function bindFilePickerInput(id,handler){
  const input=$(id); if(!input) return;
  input.addEventListener('click',()=>beginFilePicker(id));
  input.addEventListener('cancel',()=>endFilePicker());
  input.addEventListener('change',async e=>{
    filePickerSelectionStarted(id);
    try{ await handler(e); }
    finally{ e.target.value=''; endFilePicker(); }
  });
}

function resetAutoLock(){
  lastActivity=Date.now(); clearTimeout(autoLockTimer);
  if(!sessionVault) return;
  const min=Number(sessionVault.settings?.autoLockMinutes||5);
  autoLockTimer=setTimeout(()=>{
    // Never lock while the system photo/file picker is open or a selected file is
    // actively being encrypted. This is important on iOS PWAs where the picker
    // temporarily moves the web app out of the foreground.
    if(systemPickerActive){
      lastActivity=Date.now();
      resetAutoLock();
      return;
    }
    if(Date.now()-lastActivity>=min*60000) lockVault(); else resetAutoLock();
  },min*60000+250);
}

function renderAll(){
  if(!sessionVault)return;
  renderPasswords(); renderNotes();
  $('pwCount').textContent=sessionVault.passwords.length;
  $('noteCount').textContent=sessionVault.notes.length;
  const ef=$('externalFileCount'); if(ef) ef.textContent=String(externalVault?.items?.length||0);
  $('autoLockSelect').value=String(sessionVault.settings?.autoLockMinutes||5);
  const sec=$('securityStatus'); if(sec) sec.textContent=`AES-256-GCM • 6-stellige Master-PIN • PBKDF2-SHA-256 ${PBKDF2_ITERATIONS.toLocaleString('de-DE')} • .safebase Passkey-only • Backup Passkey-only • v${DISPLAY_VERSION}`;
  renderExternalVault();
  renderExternalDraftRecovery().catch(()=>{});
  renderTwoFactorStatus();
}
function empty(msg){ const d=document.createElement('div'); d.className='empty'; d.textContent=msg; return d; }

function renderPasswords(){
  const list=$('passwordList'); list.textContent='';
  const q=$('searchPasswords').value.trim().toLowerCase();
  const items=sessionVault.passwords.filter(x=>[x.name,x.username,x.website,x.note].join(' ').toLowerCase().includes(q));
  if(!items.length){list.append(empty('Noch keine passenden Passwörter.'));return;}
  items.sort((a,b)=>safeText(a.name).localeCompare(safeText(b.name),'de')).forEach(item=>{
    const c=document.createElement('div'); c.className='card';
    const title=document.createElement('div'); title.className='card-title'; title.textContent=item.name;
    const sub=document.createElement('div'); sub.className='card-sub'; sub.textContent=[item.username,item.website].filter(Boolean).join(' • ')||'Kein Benutzername';
    const acts=document.createElement('div'); acts.className='card-actions';
    acts.append(mini('Passwort kopieren',()=>copyText(item.password)),mini('Bearbeiten',()=>openPasswordDialog(item)),mini('Löschen',()=>deletePassword(item.id),true));
    c.append(title,sub,acts); list.append(c);
  });
}
function mini(label,fn,danger=false){ const b=document.createElement('button');b.type='button';b.className='mini'+(danger?' danger-mini':'');b.textContent=label;b.addEventListener('click',fn);return b; }
async function textFingerprint(text){
  const hash=await crypto.subtle.digest('SHA-256',enc.encode(text));
  return b64(new Uint8Array(hash));
}
async function copyText(text){
  try{
    const fingerprint=await textFingerprint(text);
    await navigator.clipboard.writeText(text);
    toast('Kopiert • Löschung nach 30 Sekunden wird versucht');
    clearTimeout(clipboardTimer);
    clipboardTimer=setTimeout(async()=>{
      try{
        if(document.visibilityState!=='visible' || !navigator.clipboard.readText) return;
        const current=await navigator.clipboard.readText();
        if(await textFingerprint(current)===fingerprint) await navigator.clipboard.writeText('');
      }catch{}
    },CLIPBOARD_CLEAR_MS);
  }catch{ toast('Kopieren nicht möglich'); }
}
function openPasswordDialog(item=null){
  $('passwordDialogTitle').textContent=item?'Passwort bearbeiten':'Neues Passwort';
  $('passwordId').value=item?.id||''; $('entryName').value=item?.name||''; $('entryUsername').value=item?.username||''; $('entryPassword').value=item?.password||''; $('entryWebsite').value=item?.website||''; $('entryNote').value=item?.note||''; $('entryPassword').type='password'; $('passwordDialog').showModal();
}
async function deletePassword(id){ if(!confirm('Diesen Passwort-Eintrag wirklich löschen?'))return; sessionVault.passwords=sessionVault.passwords.filter(x=>x.id!==id); await saveVault();toast('Gelöscht'); }

function renderNotes(){
  const list=$('noteList');list.textContent='';const q=$('searchNotes').value.trim().toLowerCase();
  const items=sessionVault.notes.filter(x=>[x.title,x.body].join(' ').toLowerCase().includes(q));
  if(!items.length){list.append(empty('Noch keine passenden Notizen.'));return;}
  items.sort((a,b)=>safeText(a.title).localeCompare(safeText(b.title),'de')).forEach(item=>{
    const c=document.createElement('div');c.className='card';const title=document.createElement('div');title.className='card-title';title.textContent=item.title;const sub=document.createElement('div');sub.className='card-sub';sub.textContent=(item.body||'').slice(0,140)||'Leere Notiz';const acts=document.createElement('div');acts.className='card-actions';acts.append(mini('Bearbeiten',()=>openNoteDialog(item)),mini('Löschen',()=>deleteNote(item.id),true));c.append(title,sub,acts);list.append(c);
  });
}
function openNoteDialog(item=null){ $('noteDialogTitle').textContent=item?'Notiz bearbeiten':'Neue Notiz';$('noteId').value=item?.id||'';$('noteTitle').value=item?.title||'';$('noteBody').value=item?.body||'';$('noteDialog').showModal(); }
async function deleteNote(id){ if(!confirm('Diese Notiz wirklich löschen?'))return;sessionVault.notes=sessionVault.notes.filter(x=>x.id!==id);await saveVault();toast('Gelöscht'); }

function externalFormatBytes(n){
  n=Number(n)||0;
  if(n<1024)return `${n} B`;
  if(n<1048576)return `${(n/1024).toFixed(1)} KB`;
  if(n<1073741824)return `${(n/1048576).toFixed(1)} MB`;
  return `${(n/1073741824).toFixed(2)} GB`;
}
function externalIsImage(item){
  if((item?.type||'').toLowerCase().startsWith('image/')) return true;
  return /\.(jpe?g|png|gif|webp|heic|heif|avif)$/i.test(item?.name||'');
}
function externalU32(value){
  if(!Number.isInteger(value) || value<0 || value>0xffffffff) throw new Error('Dateigröße außerhalb des unterstützten Bereichs');
  const b=new Uint8Array(4); new DataView(b.buffer).setUint32(0,value,false); return b;
}
function externalConcat(...parts){
  const arrays=parts.map(x=>x instanceof Uint8Array?x:new Uint8Array(x));
  const total=arrays.reduce((n,x)=>n+x.length,0); const out=new Uint8Array(total); let pos=0;
  for(const a of arrays){out.set(a,pos);pos+=a.length;} return out;
}
function externalLegacyHeaderBytes(salt,manifestIv,manifestLength){
  if(!(salt instanceof Uint8Array)||salt.length!==16) throw new Error('Ungültiger Tresor-Salt');
  if(!(manifestIv instanceof Uint8Array)||manifestIv.length!==12) throw new Error('Ungültiger Manifest-IV');
  const out=new Uint8Array(40);
  out.set(EXTERNAL_MAGIC,0); out[4]=EXTERNAL_VAULT_LEGACY_VERSION;
  out.set(salt,8); out.set(manifestIv,24); out.set(externalU32(manifestLength),36);
  return out;
}
function externalV2HeaderBytes({salt,manifestIv,manifestLength,credentialId,prfSalt,rpId}){
  if(!(salt instanceof Uint8Array)||salt.length!==16) throw new Error('Ungültiger Tresor-Salt');
  if(!(manifestIv instanceof Uint8Array)||manifestIv.length!==12) throw new Error('Ungültiger Manifest-IV');
  if(!(credentialId instanceof Uint8Array)||!credentialId.length||credentialId.length>1024) throw new Error('Ungültige Passkey-ID');
  if(!(prfSalt instanceof Uint8Array)||prfSalt.length!==32) throw new Error('Ungültiger Passkey-Salt');
  const meta={
    format:'SafeBaseExternalVaultHeader',version:EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION,
    kdf:{name:'PBKDF2',hash:'SHA-256',iterations:EXTERNAL_VAULT_ITERATIONS,salt:b64(salt)},
    manifest:{iv:b64(manifestIv),length:manifestLength},
    webauthn:{type:'public-key',credentialId:b64(credentialId),prfSalt:b64(prfSalt),rpId:safeText(rpId||location.hostname)}
  };
  const metaBytes=enc.encode(JSON.stringify(meta));
  if(metaBytes.length>8192) throw new Error('Tresor-Header ist zu groß');
  const prefix=new Uint8Array(9); prefix.set(EXTERNAL_MAGIC,0); prefix[4]=EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION; prefix.set(externalU32(metaBytes.length),5);
  return externalConcat(prefix,metaBytes);
}
function externalV3HeaderBytes({kdfSalt,manifestIv,manifestLength,credentialId,prfSalt,rpId,passkeyLabel}){
  if(!(kdfSalt instanceof Uint8Array)||kdfSalt.length!==32) throw new Error('Ungültiger Tresor-KDF-Salt');
  if(!(manifestIv instanceof Uint8Array)||manifestIv.length!==12) throw new Error('Ungültiger Manifest-IV');
  if(!(credentialId instanceof Uint8Array)||!credentialId.length||credentialId.length>1024) throw new Error('Ungültige Passkey-ID');
  if(!(prfSalt instanceof Uint8Array)||prfSalt.length!==32) throw new Error('Ungültiger Passkey-Salt');
  const meta={
    format:'SafeBaseExternalVaultHeader',version:EXTERNAL_VAULT_VERSION,
    kdf:{name:'HKDF',hash:'SHA-256',salt:b64(kdfSalt),info:EXTERNAL_V3_HKDF_INFO},
    manifest:{iv:b64(manifestIv),length:manifestLength},
    webauthn:{type:'public-key',credentialId:b64(credentialId),prfSalt:b64(prfSalt),rpId:safeText(rpId||location.hostname),label:safeText(passkeyLabel||'').slice(0,64)}
  };
  const metaBytes=enc.encode(JSON.stringify(meta));
  if(metaBytes.length>8192) throw new Error('Tresor-Header ist zu groß');
  const prefix=new Uint8Array(9); prefix.set(EXTERNAL_MAGIC,0); prefix[4]=EXTERNAL_VAULT_VERSION; prefix.set(externalU32(metaBytes.length),5);
  return externalConcat(prefix,metaBytes);
}
function externalCheckMagic(b){
  if(b.length<5) throw new Error('Tresordatei zu kurz');
  for(let i=0;i<4;i++) if(b[i]!==EXTERNAL_MAGIC[i]) throw new Error('Keine SafeBase-v5-Tresordatei');
}
async function externalReadFileHeader(file){
  if(!file || file.size<9) throw new Error('Tresordatei zu kurz');
  const first=new Uint8Array(await file.slice(0,9).arrayBuffer()); externalCheckMagic(first);
  const version=first[4];
  if(version===EXTERNAL_VAULT_LEGACY_VERSION){
    if(file.size<40) throw new Error('Tresordatei zu kurz');
    const b=new Uint8Array(await file.slice(0,40).arrayBuffer());
    const manifestLength=new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(36,false);
    if(manifestLength<16 || manifestLength>32*1024*1024) throw new Error('Ungültige Manifestgröße');
    return {version,headerLength:40,salt:b.slice(8,24),manifestIv:b.slice(24,36),manifestLength};
  }
  if(version!==EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION && version!==EXTERNAL_VAULT_VERSION) throw new Error('Nicht unterstützte Tresordatei-Version');
  const metaLength=new DataView(first.buffer,first.byteOffset,first.byteLength).getUint32(5,false);
  if(metaLength<80 || metaLength>8192 || 9+metaLength>file.size) throw new Error('Ungültiger Tresor-Header');
  let meta;
  try{meta=JSON.parse(dec.decode(new Uint8Array(await file.slice(9,9+metaLength).arrayBuffer())));}catch{throw new Error('Beschädigter Tresor-Header');}
  if(meta?.format!=='SafeBaseExternalVaultHeader'||meta?.version!==version) throw new Error('Ungültiger Tresor-Header');
  const manifestIv=unb64(meta?.manifest?.iv), credentialId=unb64(meta?.webauthn?.credentialId), prfSalt=unb64(meta?.webauthn?.prfSalt), rpId=safeText(meta?.webauthn?.rpId||''), passkeyLabel=safeText(meta?.webauthn?.label||'').slice(0,64);
  const manifestLength=Number(meta?.manifest?.length);
  if(manifestIv.length!==12||prfSalt.length!==32||!credentialId.length||credentialId.length>1024||!rpId) throw new Error('Ungültige Tresor-Schlüsseldaten');
  if(rpId!==location.hostname) throw new Error(`Diese Tresordatei ist an ${rpId} gebunden. Öffne SafeBase unter genau dieser Webadresse.`);
  if(!Number.isInteger(manifestLength)||manifestLength<16||manifestLength>32*1024*1024) throw new Error('Ungültige Manifestgröße');
  if(version===EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION){
    if(meta?.kdf?.name!=='PBKDF2'||meta?.kdf?.hash!=='SHA-256'||Number(meta?.kdf?.iterations)!==EXTERNAL_VAULT_ITERATIONS) throw new Error('Nicht unterstützte Schlüsselableitung');
    const salt=unb64(meta.kdf.salt);
    if(salt.length!==16) throw new Error('Ungültiger Tresor-Salt');
    return {version,headerLength:9+metaLength,salt,manifestIv,manifestLength,credentialId,prfSalt,rpId};
  }
  if(meta?.kdf?.name!=='HKDF'||meta?.kdf?.hash!=='SHA-256'||safeText(meta?.kdf?.info)!==EXTERNAL_V3_HKDF_INFO) throw new Error('Nicht unterstützte Schlüsselableitung');
  const kdfSalt=unb64(meta.kdf.salt);
  if(kdfSalt.length!==32) throw new Error('Ungültiger Tresor-KDF-Salt');
  return {version,headerLength:9+metaLength,kdfSalt,manifestIv,manifestLength,credentialId,prfSalt,rpId,passkeyLabel};
}
async function deriveExternalPasswordBits(password,salt){
  if(typeof password!=='string' || password.length<16) throw new Error('Tresordatei-Passwort muss mindestens 16 Zeichen haben');
  const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:EXTERNAL_VAULT_ITERATIONS,hash:'SHA-256'},material,256));
}
async function deriveExternalVaultKeyLegacy(password,salt){ return deriveKey(password,salt,EXTERNAL_VAULT_ITERATIONS); }
async function deriveExternalVaultKeyV2(password,salt,prfSecret){
  if(!(prfSecret instanceof Uint8Array)||prfSecret.length!==32) throw new Error('Ungültiger Sicherheitsschlüssel');
  const pwBits=await deriveExternalPasswordBits(password,salt); const combined=externalConcat(pwBits,prfSecret);
  try{
    const material=await crypto.subtle.importKey('raw',combined,'HKDF',false,['deriveKey']);
    return await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:enc.encode('SafeBase External Vault v2 / password+WebAuthn-PRF')},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }finally{wipe(pwBits);wipe(combined);}
}
async function deriveExternalVaultKeyV3(prfSecret,kdfSalt){
  if(!(prfSecret instanceof Uint8Array)||prfSecret.length!==32) throw new Error('Ungültiger Sicherheitsschlüssel');
  if(!(kdfSalt instanceof Uint8Array)||kdfSalt.length!==32) throw new Error('Ungültiger Tresor-KDF-Salt');
  const material=await crypto.subtle.importKey('raw',prfSecret,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:kdfSalt,info:enc.encode(EXTERNAL_V3_HKDF_INFO)},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function externalRequirePasskey(){
  if(!window.PublicKeyCredential || !navigator.credentials?.create || !navigator.credentials?.get) throw new Error('Dieser Browser unterstützt Sicherheitsschlüssel/Passkeys nicht');
}
function externalWebAuthnError(err,action='bestätigt'){
  if(err?.name==='NotAllowedError'||err?.name==='AbortError') return new Error(`Sicherheitsschlüssel/Passkey wurde nicht ${action}`);
  if(err?.name==='InvalidStateError') return new Error('Dieser Sicherheitsschlüssel ist bereits registriert');
  if(err?.name==='NotSupportedError') return new Error('Der gewählte Sicherheitsschlüssel unterstützt die benötigte PRF-Funktion nicht');
  return new Error(err?.message||'Sicherheitsschlüssel konnte nicht verwendet werden');
}
async function externalGetPasskeyPrf(credentialId,prfSalt){
  externalRequirePasskey();
  const previousPicker=systemPickerActive; systemPickerActive=true; clearTimeout(autoLockTimer);
  try{
    let assertion;
    try{
      assertion=await navigator.credentials.get({publicKey:{
        challenge:randomBytes(32),
        allowCredentials:[{type:'public-key',id:credentialId}],
        timeout:120000,userVerification:'preferred',
        extensions:{prf:{eval:{first:prfSalt}}}
      }});
    }catch(err){throw externalWebAuthnError(err,'bestätigt');}
    if(!assertion || b64(new Uint8Array(assertion.rawId))!==b64(credentialId)) throw new Error('Falscher Sicherheitsschlüssel/Passkey');
    const first=assertion.getClientExtensionResults?.()?.prf?.results?.first;
    if(!first) throw new Error('Dieser Sicherheitsschlüssel liefert keinen WebAuthn-PRF-Schlüssel');
    const secret=new Uint8Array(first);
    if(secret.length!==32) throw new Error('Ungültige PRF-Antwort des Sicherheitsschlüssels');
    return new Uint8Array(secret);
  }finally{systemPickerActive=previousPicker;if(sessionVault)resetAutoLock();}
}
function defaultExternalVaultLabel(){
  const d=new Date();
  const pad=n=>String(n).padStart(2,'0');
  return `SafeBase-${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
}
function sanitizeExternalVaultLabel(value){
  return safeText(value).replace(/[\/:*?"<>|\u0000-\u001f]/g,'-').replace(/\s+/g,' ').replace(/[. ]+$/g,'').trim().slice(0,64);
}
function externalVaultFilenameFromLabel(label){
  const clean=sanitizeExternalVaultLabel(label)||defaultExternalVaultLabel();
  return `${clean}.safebase`;
}
function requestExternalVaultLabel(){
  return new Promise(resolve=>{
    const dialog=$('externalVaultNameDialog'),input=$('externalVaultNameInput');
    if(!dialog||!input){resolve(defaultExternalVaultLabel());return;}
    if(externalVaultNameResolver){externalVaultNameResolver(null);externalVaultNameResolver=null;}
    externalVaultNameResolver=resolve;
    input.value=defaultExternalVaultLabel();
    dialog.showModal();
    setTimeout(()=>{input.focus();input.select();},0);
  });
}
async function externalCreatePasskey(prfSalt,passkeyLabel){
  externalRequirePasskey();
  const label=sanitizeExternalVaultLabel(passkeyLabel)||defaultExternalVaultLabel();
  const userId=randomBytes(32); const previousPicker=systemPickerActive; systemPickerActive=true; clearTimeout(autoLockTimer);
  try{
    let credential;
    try{
      credential=await navigator.credentials.create({publicKey:{
        challenge:randomBytes(32),
        rp:{name:'SafeBase'},
        user:{id:userId,name:label,displayName:label},
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
        timeout:120000,attestation:'none',
        authenticatorSelection:{residentKey:'preferred',userVerification:'preferred'},
        extensions:{prf:{eval:{first:prfSalt}}}
      }});
    }catch(err){throw externalWebAuthnError(err,'registriert');}
    if(!credential?.rawId) throw new Error('Sicherheitsschlüssel konnte nicht registriert werden');
    const ext=credential.getClientExtensionResults?.()?.prf;
    if(!ext || ext.enabled===false) throw new Error('Der gewählte Sicherheitsschlüssel/Passkey unterstützt WebAuthn PRF nicht');
    const credentialId=new Uint8Array(credential.rawId);
    let secret=ext?.results?.first?new Uint8Array(ext.results.first):null;
    if(!secret){
      toast('Schlüssel registriert – bitte zur Schlüsselableitung noch einmal bestätigen');
      secret=await externalGetPasskeyPrf(credentialId,prfSalt);
    }
    if(secret.length!==32) throw new Error('Ungültige PRF-Antwort des Sicherheitsschlüssels');
    return {credentialId,prfSecret:secret,passkeyLabel:label};
  }finally{wipe(userId);systemPickerActive=previousPicker;if(sessionVault)resetAutoLock();}
}
function clearExternalVault(render=true){
  if(externalPreviewUrl){ try{URL.revokeObjectURL(externalPreviewUrl);}catch{} externalPreviewUrl=null; }
  externalVault=null; externalSaveHandle=null; pendingExternalOpenFile=null; pendingExternalOpenHeader=null; externalVaultPasswordMode=null; externalActionItemId=null;
  if(render && $('externalVaultStatus')) renderExternalVault();
}
function externalTotalPlainBytes(vault=externalVault){ return vault?.items?.reduce((sum,x)=>sum+(Number(x.size)||0),0)||0; }
function setExternalStatus(message,state='info'){
  const el=$('externalVaultStatus'); if(!el) return; el.textContent=message; el.dataset.state=state;
}
function externalTypeLabel(item){
  const name=safeText(item?.name); const type=safeText(item?.type).toLowerCase();
  if(type==='application/pdf'||/\.pdf$/i.test(name)) return 'PDF';
  if(externalIsImage(item)){
    const m=name.match(/\.([a-z0-9]{2,6})$/i); return m?m[1].toUpperCase():'Foto';
  }
  const ext=name.match(/\.([a-z0-9]{1,8})$/i); if(ext) return ext[1].toUpperCase();
  if(type && type!=='application/octet-stream') return (type.split('/').pop()||'Datei').toUpperCase();
  return 'Datei';
}
function externalFormatDate(value,long=false){
  const d=new Date(value); if(Number.isNaN(d.getTime())) return 'Unbekannt';
  if(long) return d.toLocaleString('de-DE',{dateStyle:'medium',timeStyle:'short'});
  const now=new Date(),today=new Date(now.getFullYear(),now.getMonth(),now.getDate()),day=new Date(d.getFullYear(),d.getMonth(),d.getDate());
  const diff=Math.round((today-day)/86400000); if(diff===0)return 'Heute'; if(diff===1)return 'Gestern';
  return d.toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric'});
}
function externalFilteredItems(){
  if(!externalVault) return [];
  const q=safeText($('searchExternalFiles')?.value).trim().toLocaleLowerCase('de-DE');
  const items=externalVault.items.filter(item=>{
    const category=externalIsImage(item)?'images':'documents';
    if(externalListFilter!=='all'&&externalListFilter!==category)return false;
    return !q || `${safeText(item.name)} ${safeText(item.type)} ${externalTypeLabel(item)}`.toLocaleLowerCase('de-DE').includes(q);
  });
  items.sort((a,b)=>{
    if(externalListSort==='name') return safeText(a.name).localeCompare(safeText(b.name),'de',{numeric:true,sensitivity:'base'});
    if(externalListSort==='size') return (Number(b.size)||0)-(Number(a.size)||0);
    return safeText(b.addedAt).localeCompare(safeText(a.addedAt));
  });
  return items;
}
function openExternalItemMenu(id){
  const item=externalVault?.items?.find(x=>x.id===id); if(!item)return;
  externalActionItemId=id;
  $('externalMenuIcon').textContent=externalIsImage(item)?'🖼️':'📄';
  $('externalMenuTitle').textContent=item.name||'Datei';
  $('externalMenuMeta').textContent=`${externalTypeLabel(item)} • ${externalFormatBytes(item.size)} • ${externalFormatDate(item.addedAt)}`;
  $('externalMenuOpenBtn').textContent=externalIsImage(item)?'Vorschau öffnen':'Öffnen';
  $('externalItemMenuDialog').showModal();
}
function selectedExternalItem(){ return externalVault?.items?.find(x=>x.id===externalActionItemId)||null; }
function openExternalInfo(item){
  if(!item)return;
  $('externalInfoName').textContent=item.name||'Datei';
  $('externalInfoType').textContent=`${externalTypeLabel(item)}${item.type?` • ${item.type}`:''}`;
  $('externalInfoSize').textContent=externalFormatBytes(item.size);
  $('externalInfoDate').textContent=externalFormatDate(item.addedAt,true);
  $('externalInfoDialog').showModal();
}
function renderExternalVault(){
  const workspace=$('externalVaultWorkspace'),list=$('externalFileList'),count=$('externalFileCount');
  if(!workspace||!list) return;
  const totalCount=externalVault?.items?.length||0,totalBytes=externalTotalPlainBytes();
  if(count) count.textContent=String(totalCount);
  if($('externalVaultItemCount')) $('externalVaultItemCount').textContent=String(totalCount);
  if($('externalVaultSize')) $('externalVaultSize').textContent=externalFormatBytes(totalBytes);
  if($('externalVaultProtection')) $('externalVaultProtection').textContent=externalVault?.version===EXTERNAL_VAULT_VERSION?(externalVault.passkeyLabel||'Passkey'):'Legacy';
  list.textContent='';
  document.querySelectorAll('[data-external-filter]').forEach(btn=>btn.classList.toggle('active',btn.dataset.externalFilter===externalListFilter));
  if($('externalSortSelect')) $('externalSortSelect').value=externalListSort;
  if(!externalVault){
    workspace.classList.add('hidden');
    if($('externalVaultName')) $('externalVaultName').textContent='Keine Tresordatei geöffnet';
    const badge=$('storageVaultBadge'); if(badge){badge.textContent='Geschlossen';badge.dataset.state='closed';}
    setExternalStatus('Erstelle eine neue Tresordatei oder öffne eine vorhandene.','info');
    return;
  }
  workspace.classList.remove('hidden');
  if($('externalVaultName')) $('externalVaultName').textContent=externalVault.name||'SafeBase-Tresor.safebase';
  const badge=$('storageVaultBadge');
  if(badge){badge.textContent=externalVault.dirty?'Ungespeichert':'Entsperrt';badge.dataset.state=externalVault.dirty?'warning':'success';}
  const protection=externalVault.version===EXTERNAL_VAULT_VERSION?`Passkey: ${externalVault.passkeyLabel||'Sicherheitsschlüssel'}`:'älterer Schutz';
  const upgrade=externalVault.migratedFromLegacy?' • Sicherheitsupgrade aktiv':'';
  setExternalStatus(`Entsperrt • ${protection}${upgrade}${externalVault.dirty?' • Änderungen noch nicht gesichert':''}`,externalVault.dirty?'warning':'success');
  if($('externalListSummary')) $('externalListSummary').textContent=`${totalCount} Datei${totalCount===1?'':'en'} • ${externalFormatBytes(totalBytes)}`;
  if(!totalCount){ list.append(empty('Noch keine Fotos oder Dokumente gespeichert.')); return; }
  const items=externalFilteredItems();
  if(!items.length){ list.append(empty('Keine Dateien für diese Suche oder Auswahl.')); return; }
  for(const item of items){
    const row=document.createElement('div'); row.className='storage-file-row';
    const icon=document.createElement('div'); icon.className='storage-file-icon'; icon.textContent=externalIsImage(item)?'🖼️':'📄';
    const body=document.createElement('div'); body.className='storage-file-body';
    const title=document.createElement('div'); title.className='storage-file-name'; title.textContent=item.name||'Datei'; title.title=item.name||'Datei';
    const sub=document.createElement('div'); sub.className='storage-file-meta'; sub.textContent=`${externalTypeLabel(item)} • ${externalFormatBytes(item.size)} • ${externalFormatDate(item.addedAt)}`;
    body.append(title,sub);
    const menu=document.createElement('button'); menu.type='button'; menu.className='storage-file-menu'; menu.textContent='•••'; menu.setAttribute('aria-label',`Aktionen für ${item.name||'Datei'}`); menu.addEventListener('click',()=>openExternalItemMenu(item.id));
    row.append(icon,body,menu); list.append(row);
  }
}
function openExternalLegacyPasswordDialog(header){
  externalVaultPasswordMode='legacy-open';
  const form=$('externalVaultPasswordForm'); form.reset();
  const isV1=header?.version===EXTERNAL_VAULT_LEGACY_VERSION;
  $('externalVaultPasswordTitle').textContent='Ältere Tresordatei öffnen';
  $('externalVaultPasswordHint').textContent=isV1
    ?'Diese ältere Tresordatei ist noch passwortgeschützt. Gib einmalig ihr altes Passwort ein. Danach richtest du einen Passkey/Sicherheitsschlüssel ein und kannst sie beim nächsten Speichern auf Passkey-only aktualisieren.'
    :'Diese v5.1-Tresordatei verwendet noch Passwort + Passkey. Gib einmalig das bisherige Tresordatei-Passwort ein. Danach wird sie beim nächsten Speichern auf Passkey-only aktualisiert.';
  $('externalVaultPasswordConfirmWrap').classList.add('hidden');
  const submit=$('externalVaultPasswordSubmit'); if(submit) submit.textContent='Altes Passwort bestätigen';
  $('externalVaultPasswordDialog').showModal();
}
async function beginNewExternalVault(){
  if(externalVault?.dirty && !confirm('Die geöffnete Tresordatei enthält ungespeicherte Änderungen. Trotzdem eine neue erstellen?')) return;
  pendingExternalOpenFile=null; pendingExternalOpenHeader=null;
  const btn=$('newExternalVaultBtn'); if(btn) btn.disabled=true;
  try{
    const passkeyLabel=await requestExternalVaultLabel();
    if(!passkeyLabel)return;
    await createExternalVaultWithPasskey(passkeyLabel);
  }catch(err){toast(err?.message||'Passkey-Tresordatei konnte nicht erstellt werden');}
  finally{if(btn) btn.disabled=false;}
}
async function chooseExternalVaultFile(file,skipDirtyConfirm=false){
  if(!file) return;
  if(!skipDirtyConfirm && externalVault?.dirty && !confirm('Die geöffnete Tresordatei enthält ungespeicherte Änderungen. Trotzdem eine andere öffnen?')) return;
  const header=await externalReadFileHeader(file);
  pendingExternalOpenFile=file; pendingExternalOpenHeader=header;
  if(header.version===EXTERNAL_VAULT_VERSION){
    try{ await loadExternalVaultPasskeyOnly(); }
    catch(err){ pendingExternalOpenFile=null; pendingExternalOpenHeader=null; throw err; }
  }else openExternalLegacyPasswordDialog(header);
}
async function createExternalVaultWithPasskey(passkeyLabel){
  const label=sanitizeExternalVaultLabel(passkeyLabel)||defaultExternalVaultLabel();
  const kdfSalt=randomBytes(32),prfSalt=randomBytes(32);
  toast(`Passkey „${label}“ jetzt einrichten`);
  const registered=await externalCreatePasskey(prfSalt,label);
  try{
    const key=await deriveExternalVaultKeyV3(registered.prfSecret,kdfSalt);
    externalVault={name:externalVaultFilenameFromLabel(registered.passkeyLabel),passkeyLabel:registered.passkeyLabel,version:EXTERNAL_VAULT_VERSION,kdfSalt,key,credentialId:registered.credentialId,prfSalt,rpId:location.hostname,legacyKey:null,legacyKeyVersion:null,items:[],createdAt:nowISO(),updatedAt:nowISO(),dirty:true,migratedFromLegacy:false};
    markExternalVaultDirty();
  }finally{wipe(registered.prfSecret);}
  renderExternalVault(); toast(`Tresordatei erstellt • ${externalVault.name}`);
}
async function externalReadManifestAndItems(file,head,key){
  const manifestStart=head.headerLength, manifestEnd=manifestStart+head.manifestLength;
  if(manifestEnd>file.size) throw new Error('Tresordatei ist beschädigt');
  const manifestCipher=new Uint8Array(await file.slice(manifestStart,manifestEnd).arrayBuffer());
  let manifest;
  try{manifest=JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:head.manifestIv,tagLength:128,additionalData:enc.encode(externalManifestAAD(head.version))},key,manifestCipher)));}
  catch{
    if(head.version===EXTERNAL_VAULT_VERSION) throw new Error('Passkey/Sicherheitsschlüssel oder Tresordatei ist ungültig');
    if(head.version===EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION) throw new Error('Passwort, Passkey/Sicherheitsschlüssel oder Tresordatei ist ungültig');
    throw new Error('Falsches Tresordatei-Passwort oder beschädigte Datei');
  }
  if(!manifest || manifest.format!=='SafeBaseExternalVault' || manifest.version!==head.version || !Array.isArray(manifest.items)) throw new Error('Ungültiges Tresor-Manifest');
  if(manifest.items.length>5000) throw new Error('Tresordatei enthält zu viele Einträge');
  const items=[]; const seenIds=new Set(); let pos=manifestEnd,totalPlain=0;
  for(const meta of manifest.items){
    if(!meta || typeof meta.id!=='string' || !meta.id || meta.id.length>200 || seenIds.has(meta.id)) throw new Error('Ungültige oder doppelte Datei-ID im Tresor');
    seenIds.add(meta.id);
    if(typeof meta.name!=='string' || meta.name.length>500 || typeof meta.type!=='string' || meta.type.length>200) throw new Error('Ungültige Dateimetadaten im Tresor');
    const declaredSize=Number(meta.size);
    if(!Number.isSafeInteger(declaredSize) || declaredSize<0 || declaredSize>EXTERNAL_FILE_MAX_BYTES) throw new Error('Ungültige Dateigröße im Tresor');
    totalPlain+=declaredSize; if(totalPlain>EXTERNAL_VAULT_MAX_BYTES) throw new Error('Tresordatei überschreitet das Sicherheitslimit');
    if(pos+16>file.size) throw new Error('Tresordatei ist unvollständig');
    const recordHead=new Uint8Array(await file.slice(pos,pos+16).arrayBuffer()); pos+=16;
    const iv=recordHead.slice(0,12); const ctLen=new DataView(recordHead.buffer,recordHead.byteOffset,recordHead.byteLength).getUint32(12,false);
    if(ctLen<16 || pos+ctLen>file.size) throw new Error('Ungültiger Dateieintrag im Tresor');
    if(ctLen!==declaredSize+16) throw new Error('Dateigröße stimmt nicht mit dem authentifizierten Manifest überein');
    items.push({id:safeText(meta.id),name:safeText(meta.name),type:safeText(meta.type),size:declaredSize,addedAt:safeText(meta.addedAt),source:'encrypted',cryptoVersion:head.version,iv,encBlob:file.slice(pos,pos+ctLen)});
    pos+=ctLen;
  }
  if(pos!==file.size) throw new Error('Tresordatei enthält unerwartete Zusatzdaten');
  return {manifest,items};
}
async function loadExternalVaultPasskeyOnly(){
  const file=pendingExternalOpenFile; if(!file) throw new Error('Keine Tresordatei ausgewählt');
  const head=pendingExternalOpenHeader||await externalReadFileHeader(file);
  if(head.version!==EXTERNAL_VAULT_VERSION) throw new Error('Diese Tresordatei benötigt die Legacy-Migration');
  toast('Passkey oder Sicherheitsschlüssel jetzt bestätigen');
  const prfSecret=await externalGetPasskeyPrf(head.credentialId,head.prfSalt); let key;
  try{key=await deriveExternalVaultKeyV3(prfSecret,head.kdfSalt);}finally{wipe(prfSecret);}
  const parsed=await externalReadManifestAndItems(file,head,key);
  const fallbackLabel=sanitizeExternalVaultLabel((file.name||'').replace(/\.safebase$/i,''));
  externalVault={name:file.name||externalVaultFilenameFromLabel(head.passkeyLabel||fallbackLabel),passkeyLabel:head.passkeyLabel||fallbackLabel,version:EXTERNAL_VAULT_VERSION,kdfSalt:head.kdfSalt,key,credentialId:head.credentialId,prfSalt:head.prfSalt,rpId:head.rpId,legacyKey:null,legacyKeyVersion:null,items:parsed.items,createdAt:safeText(parsed.manifest.createdAt||''),updatedAt:safeText(parsed.manifest.updatedAt||''),dirty:false,migratedFromLegacy:false};
  pendingExternalOpenFile=null; pendingExternalOpenHeader=null; renderExternalVault(); toast('Tresordatei mit Passkey entsperrt');
}
async function loadLegacyExternalVaultWithPassword(password){
  const file=pendingExternalOpenFile; if(!file) throw new Error('Keine Tresordatei ausgewählt');
  const head=pendingExternalOpenHeader||await externalReadFileHeader(file);
  if(head.version===EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION){
    toast('Bisherigen Passkey oder Sicherheitsschlüssel jetzt bestätigen');
    const prfSecret=await externalGetPasskeyPrf(head.credentialId,head.prfSalt); let oldKey,newKey; const kdfSalt=randomBytes(32);
    try{
      oldKey=await deriveExternalVaultKeyV2(password,head.salt,prfSecret);
      const parsed=await externalReadManifestAndItems(file,head,oldKey);
      newKey=await deriveExternalVaultKeyV3(prfSecret,kdfSalt);
      const fallbackLabel=sanitizeExternalVaultLabel((file.name||'').replace(/\.safebase$/i,''));
      externalVault={name:file.name||externalVaultFilenameFromLabel(head.passkeyLabel||fallbackLabel),passkeyLabel:head.passkeyLabel||fallbackLabel,version:EXTERNAL_VAULT_VERSION,kdfSalt,key:newKey,credentialId:head.credentialId,prfSalt:head.prfSalt,rpId:head.rpId,legacyKey:oldKey,legacyKeyVersion:EXTERNAL_VAULT_PASSWORD_PASSKEY_VERSION,items:parsed.items,createdAt:safeText(parsed.manifest.createdAt||''),updatedAt:safeText(parsed.manifest.updatedAt||''),dirty:true,migratedFromLegacy:true};
    }finally{wipe(prfSecret);}
    pendingExternalOpenFile=null; pendingExternalOpenHeader=null; markExternalVaultDirty(); renderExternalVault(); toast('Passkey-only Upgrade aktiv • Tresordatei jetzt neu sichern'); return;
  }
  if(head.version!==EXTERNAL_VAULT_LEGACY_VERSION) throw new Error('Nicht unterstützte Legacy-Tresordatei');
  const oldKey=await deriveExternalVaultKeyLegacy(password,head.salt);
  const parsed=await externalReadManifestAndItems(file,head,oldKey);
  const upgradeLabel=await requestExternalVaultLabel();
  if(!upgradeLabel) throw new Error('Passkey-Upgrade abgebrochen');
  toast(`Alte Datei entsperrt • Passkey „${upgradeLabel}“ jetzt für das Upgrade einrichten`);
  const prfSalt=randomBytes(32),registered=await externalCreatePasskey(prfSalt,upgradeLabel),kdfSalt=randomBytes(32); let newKey;
  try{newKey=await deriveExternalVaultKeyV3(registered.prfSecret,kdfSalt);}finally{wipe(registered.prfSecret);}
  externalVault={name:externalVaultFilenameFromLabel(registered.passkeyLabel),passkeyLabel:registered.passkeyLabel,version:EXTERNAL_VAULT_VERSION,kdfSalt,key:newKey,credentialId:registered.credentialId,prfSalt,rpId:location.hostname,legacyKey:oldKey,legacyKeyVersion:EXTERNAL_VAULT_LEGACY_VERSION,items:parsed.items,createdAt:safeText(parsed.manifest.createdAt||''),updatedAt:safeText(parsed.manifest.updatedAt||''),dirty:true,migratedFromLegacy:true};
  pendingExternalOpenFile=null; pendingExternalOpenHeader=null; markExternalVaultDirty(); renderExternalVault(); toast('Passkey-only Upgrade aktiv • Tresordatei jetzt neu sichern');
}
async function addExternalFiles(fileList){
  if(!externalVault) return toast('Zuerst eine Tresordatei erstellen oder öffnen');
  const files=[...(fileList||[])]; if(!files.length) return;
  const current=externalTotalPlainBytes(); let running=current,added=0;
  for(const file of files){
    if(file.size>EXTERNAL_FILE_MAX_BYTES){ toast(`${file.name}: maximal ${externalFormatBytes(EXTERNAL_FILE_MAX_BYTES)} pro Datei`); continue; }
    if(running+file.size>EXTERNAL_VAULT_MAX_BYTES){ toast(`Tresordatei-Limit erreicht (${externalFormatBytes(EXTERNAL_VAULT_MAX_BYTES)})`); break; }
    externalVault.items.push({id:uuid(),name:safeText(file.name||`Datei-${Date.now()}`).slice(0,500),type:safeText(file.type||'application/octet-stream').slice(0,200),size:file.size,addedAt:nowISO(),source:'plain',blob:file});
    running+=file.size; added++;
  }
  if(added){ externalVault.updatedAt=nowISO(); markExternalVaultDirty(); renderExternalVault(); toast(`${added} Datei${added===1?'':'en'} hinzugefügt – jetzt Tresordatei sichern`); }
}
async function externalPlainBlob(item,vault=externalVault){
  if(item.source==='plain' && item.blob) return item.blob;
  if(item.source==='encrypted' && item.encBlob){
    const ct=new Uint8Array(await item.encBlob.arrayBuffer());
    const cryptoVersion=item.cryptoVersion||vault?.version||EXTERNAL_VAULT_VERSION;
    const key=cryptoVersion===vault?.version ? vault.key : (vault?.legacyKey && vault.legacyKeyVersion===cryptoVersion ? vault.legacyKey : null);
    if(!key) throw new Error('Entschlüsselungsschlüssel fehlt');
    let pt;
    try{pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:item.iv,tagLength:128,additionalData:enc.encode(externalFileAAD(item.id,cryptoVersion))},key,ct);}
    catch{throw new Error('Datei-Authentifizierung fehlgeschlagen');}
    return new Blob([pt],{type:item.type||'application/octet-stream'});
  }
  throw new Error('Dateidaten fehlen');
}
async function openExternalItem(id){
  const item=externalVault?.items?.find(x=>x.id===id); if(!item) return;
  try{
    const blob=await externalPlainBlob(item);
    if(externalIsImage(item)){
      closeExternalPreview(); externalPreviewUrl=URL.createObjectURL(blob); $('externalPreviewImage').src=externalPreviewUrl; $('externalPreviewName').textContent=item.name||'Foto'; $('externalPreviewDialog').showModal(); return;
    }
    await exportDecryptedExternalItem(item,blob);
  }catch(e){toast(e?.message||'Datei konnte nicht entschlüsselt werden');}
}
async function exportDecryptedExternalItem(item,blob=null){
  blob=blob||await externalPlainBlob(item);
  const fileObj=new File([blob],item.name||'SafeBase-Datei',{type:item.type||'application/octet-stream'});
  systemPickerActive=true; clearTimeout(autoLockTimer);
  try{
    if(navigator.share && navigator.canShare?.({files:[fileObj]})) await navigator.share({files:[fileObj],title:item.name||'SafeBase-Datei'});
    else{ const url=URL.createObjectURL(fileObj); const a=document.createElement('a'); a.href=url; a.download=fileObj.name; a.rel='noopener'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),60000); }
  }catch(e){ if(e?.name!=='AbortError') toast('Export nicht möglich'); }
  finally{ systemPickerActive=false; if(sessionVault) resetAutoLock(); }
}
function closeExternalPreview(){
  const d=$('externalPreviewDialog'); if(d?.open)d.close(); const img=$('externalPreviewImage'); if(img)img.removeAttribute('src');
  if(externalPreviewUrl){ try{URL.revokeObjectURL(externalPreviewUrl);}catch{} externalPreviewUrl=null; }
}
function deleteExternalItem(id){
  if(!externalVault || !confirm('Diese Datei aus der geöffneten Tresordatei entfernen? Danach Tresordatei erneut sichern.')) return;
  externalVault.items=externalVault.items.filter(x=>x.id!==id); externalVault.updatedAt=nowISO(); markExternalVaultDirty(); renderExternalVault(); toast('Entfernt – Tresordatei erneut sichern');
}
async function buildExternalVaultFile(vault=externalVault){
  if(!vault) throw new Error('Keine Tresordatei geöffnet');
  if(vault.version!==EXTERNAL_VAULT_VERSION||!vault.credentialId||!vault.prfSalt) throw new Error('Tresordatei hat keinen aktiven Sicherheitsschlüssel');
  if(externalTotalPlainBytes(vault)>EXTERNAL_VAULT_MAX_BYTES) throw new Error('Tresordatei ist zu groß');
  const manifest={format:'SafeBaseExternalVault',version:EXTERNAL_VAULT_VERSION,kdf:{name:'HKDF',hash:'SHA-256',info:EXTERNAL_V3_HKDF_INFO},keyProtection:{type:'WebAuthn-PRF-only'},createdAt:vault.createdAt||nowISO(),updatedAt:nowISO(),items:vault.items.map(x=>({id:x.id,name:x.name,type:x.type,size:x.size,addedAt:x.addedAt}))};
  const manifestIv=randomBytes(12);
  const manifestCipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:manifestIv,tagLength:128,additionalData:enc.encode(externalManifestAAD(EXTERNAL_VAULT_VERSION))},vault.key,enc.encode(JSON.stringify(manifest))));
  const header=externalV3HeaderBytes({kdfSalt:vault.kdfSalt,manifestIv,manifestLength:manifestCipher.length,credentialId:vault.credentialId,prfSalt:vault.prfSalt,rpId:vault.rpId||location.hostname,passkeyLabel:vault.passkeyLabel});
  const chunks=[header,manifestCipher];
  for(let i=0;i<vault.items.length;i++){
    const item=vault.items[i]; let iv,ctBlob;
    if(item.source==='encrypted'&&item.encBlob&&item.iv&&item.cryptoVersion===EXTERNAL_VAULT_VERSION){iv=item.iv;ctBlob=item.encBlob;}
    else{
      const source=await externalPlainBlob(item,vault); const bytes=new Uint8Array(await source.arrayBuffer());
      try{
        iv=randomBytes(12);
        const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,tagLength:128,additionalData:enc.encode(externalFileAAD(item.id,EXTERNAL_VAULT_VERSION))},vault.key,bytes);
        ctBlob=new Blob([ct],{type:'application/octet-stream'});
      }finally{wipe(bytes);}
      item.source='encrypted'; item.cryptoVersion=EXTERNAL_VAULT_VERSION; item.iv=iv; item.encBlob=ctBlob; delete item.blob;
    }
    if(ctBlob.size!==Number(item.size)+16) throw new Error(`Verschlüsselungsgröße ungültig: ${item.name}`);
    chunks.push(iv,externalU32(ctBlob.size),ctBlob);
  }
  vault.updatedAt=manifest.updatedAt; vault.legacyKey=null; vault.legacyKeyVersion=null; vault.migratedFromLegacy=false;
  const name=vault.passkeyLabel?externalVaultFilenameFromLabel(vault.passkeyLabel):((vault.name&&vault.name.toLowerCase().endsWith('.safebase'))?vault.name:'SafeBase-Fotos-Dateien.safebase');
  return new File(chunks,name,{type:'application/octet-stream'});
}
async function getExternalDraft(){
  try{ return await idbGet('meta',EXTERNAL_DRAFT_KEY); }catch{ return null; }
}
async function renderExternalDraftRecovery(){
  const wrap=$('externalDraftRecovery'); if(!wrap||!db) return;
  const draft=await getExternalDraft();
  const sameActive=!!(draft&&externalVault?.dirty&&safeText(draft.name)===safeText(externalVault.name));
  wrap.classList.toggle('hidden',!draft||sameActive);
  if(draft&&!sameActive){
    const when=new Date(draft.updatedAt||0);
    $('externalDraftRecoveryText').textContent=`Verschlüsselter Entwurf gefunden: ${draft.name||'SafeBase-Tresor.safebase'}${Number.isNaN(when.getTime())?'':` • ${when.toLocaleString('de-DE')}`}.`;
  }
}
async function persistExternalDraft(){
  const vault=externalVault;
  if(!vault?.dirty) return;
  const revision=externalDraftRevision;
  const fileObj=await buildExternalVaultFile(vault);
  await idbPut('meta',{kind:'SafeBaseExternalDraft',version:1,name:fileObj.name,updatedAt:nowISO(),file:fileObj},EXTERNAL_DRAFT_KEY);
  if(externalVault===vault) externalDraftSavedRevision=revision;
  externalDraftWarningShown=false;
  await renderExternalDraftRecovery();
}
function queueExternalDraftSave(){
  if(!externalVault?.dirty || externalDraftSavedRevision===externalDraftRevision) return;
  if(externalDraftSavePromise) return;
  externalDraftSavePromise=persistExternalDraft()
    .catch(()=>{ if(!externalDraftWarningShown){externalDraftWarningShown=true;toast('Entwurf konnte nicht lokal gesichert werden • bitte Tresordatei manuell sichern');} })
    .finally(()=>{
      externalDraftSavePromise=null;
      if(externalVault?.dirty && externalDraftSavedRevision!==externalDraftRevision) queueExternalDraftSave();
    });
}
function markExternalVaultDirty(){
  if(!externalVault) return;
  externalVault.dirty=true;
  externalDraftRevision++;
  queueExternalDraftSave();
}
async function clearExternalDraft(){
  try{ if(externalDraftSavePromise) await externalDraftSavePromise; }catch{}
  try{ await idbDelete('meta',EXTERNAL_DRAFT_KEY); }catch{}
  externalDraftSavedRevision=-1;
  await renderExternalDraftRecovery();
}
async function recoverExternalDraft(){
  const draft=await getExternalDraft();
  if(!draft?.file) return toast('Kein wiederherstellbarer Entwurf vorhanden');
  if(externalVault?.dirty&&!confirm('Der aktuell geöffnete Tresor enthält ungespeicherte Änderungen. Wiederherstellungsentwurf trotzdem öffnen?')) return;
  try{
    await chooseExternalVaultFile(draft.file,true);
    if(externalVault){ markExternalVaultDirty(); renderExternalVault(); toast('Entwurf wiederhergestellt • jetzt in Dateien sichern'); }
  }catch(err){ toast(err?.message||'Entwurf konnte nicht wiederhergestellt werden'); }
}
async function discardExternalDraft(){
  if(!confirm('Wiederherstellungsentwurf endgültig löschen?')) return;
  try{ await idbDelete('meta',EXTERNAL_DRAFT_KEY); }catch{}
  externalDraftSavedRevision=-1;
  await renderExternalDraftRecovery();
  toast('Wiederherstellungsentwurf gelöscht');
}

async function saveExternalVaultToFiles(){
  if(!externalVault) return toast('Keine Tresordatei geöffnet');
  const btn=$('saveExternalVaultBtn'); btn.disabled=true; const old=btn.textContent; btn.textContent='Verschlüssele …';
  systemPickerActive=true; clearTimeout(autoLockTimer);
  try{
    if(externalDraftSavePromise) await externalDraftSavePromise;
    const fileObj=await buildExternalVaultFile();
    if(typeof window.showSaveFilePicker==='function'){
      try{
        const handle=await window.showSaveFilePicker({suggestedName:fileObj.name,types:[{description:'SafeBase Tresordatei',accept:{'application/octet-stream':['.safebase']}}]});
        const writable=await handle.createWritable(); await writable.write(fileObj); await writable.close(); externalSaveHandle=handle;
        externalVault.name=handle.name||fileObj.name; externalVault.dirty=false; await clearExternalDraft(); renderExternalVault(); toast('Tresordatei Passkey-only gespeichert'); return;
      }catch(e){if(e?.name==='AbortError')return;}
    }
    if(navigator.share && navigator.canShare?.({files:[fileObj]})){
      await navigator.share({files:[fileObj],title:'SafeBase Tresordatei'});
      renderExternalVault(); toast('Freigabe abgeschlossen • erst nach „In Dateien sichern“ ist der Tresor dauerhaft gespeichert'); return;
    }
    const url=URL.createObjectURL(fileObj); const a=document.createElement('a'); a.href=url; a.download=fileObj.name; a.rel='noopener'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(url),60000);
    externalVault.dirty=false; await clearExternalDraft(); renderExternalVault(); toast('Tresordatei als Download erstellt');
  }catch(e){if(e?.name!=='AbortError')toast(e?.message||'Tresordatei konnte nicht gespeichert werden');}
  finally{systemPickerActive=false;btn.disabled=false;btn.textContent=old;if(sessionVault)resetAutoLock();}
}

function generatePassword(){
  const sets=[]; if($('useUpper').checked)sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ');if($('useLower').checked)sets.push('abcdefghijkmnopqrstuvwxyz');if($('useNumbers').checked)sets.push('23456789');if($('useSymbols').checked)sets.push('!@#$%&*+-_=?:.,');
  if(!sets.length){toast('Mindestens eine Zeichengruppe auswählen');return;}
  const all=sets.join('');const len=Number($('lengthSlider').value);let chars=[];sets.forEach(s=>chars.push(s[randomIndex(s.length)]));while(chars.length<len)chars.push(all[randomIndex(all.length)]);for(let i=chars.length-1;i>0;i--){const j=randomIndex(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}$('generatedPassword').value=chars.join('');
}
function randomIndex(max){ const limit=Math.floor(0x100000000/max)*max;const a=new Uint32Array(1);do{crypto.getRandomValues(a);}while(a[0]>=limit);return a[0]%max; }


const BASE32_ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes){
  let bits=0,value=0,out='';
  for(const byte of bytes){
    value=(value<<8)|byte; bits+=8;
    while(bits>=5){ out+=BASE32_ALPHABET[(value >>> (bits-5)) & 31]; bits-=5; }
  }
  if(bits>0) out+=BASE32_ALPHABET[(value << (5-bits)) & 31];
  return out;
}
function base32Decode(text){
  const clean=safeText(text).toUpperCase().replace(/[^A-Z2-7]/g,'');
  if(!clean) throw new Error('Ungültiger 2FA-Schlüssel');
  let bits=0,value=0; const out=[];
  for(const ch of clean){
    const idx=BASE32_ALPHABET.indexOf(ch); if(idx<0) throw new Error('Ungültiger 2FA-Schlüssel');
    value=(value<<5)|idx; bits+=5;
    if(bits>=8){ out.push((value >>> (bits-8)) & 255); bits-=8; }
  }
  return new Uint8Array(out);
}
function normalizeTotpCode(code){ return safeText(code).replace(/\D/g,'').slice(0,TOTP_DIGITS); }
function normalizeRecoveryCode(code){ return safeText(code).toUpperCase().replace(/[^A-Z2-7]/g,''); }
async function sha256Text(text){ const h=await crypto.subtle.digest('SHA-256',enc.encode(text)); return b64(new Uint8Array(h)); }
async function totpAt(secretBase32,timeMs=Date.now(),digits=TOTP_DIGITS,period=TOTP_PERIOD_SECONDS){
  const secret=base32Decode(secretBase32);
  try{
    const counter=Math.floor(timeMs/1000/period);
    const msg=new Uint8Array(8); const view=new DataView(msg.buffer);
    const hi=Math.floor(counter/0x100000000); const lo=counter>>>0;
    view.setUint32(0,hi,false); view.setUint32(4,lo,false);
    const key=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-1'},false,['sign']);
    const mac=new Uint8Array(await crypto.subtle.sign('HMAC',key,msg));
    const offset=mac[mac.length-1]&0x0f;
    const bin=((mac[offset]&0x7f)<<24)|((mac[offset+1]&0xff)<<16)|((mac[offset+2]&0xff)<<8)|(mac[offset+3]&0xff);
    return String(bin % (10**digits)).padStart(digits,'0');
  } finally { wipe(secret); }
}
async function verifyTotp(secretBase32,code,timeMs=Date.now()){
  const clean=normalizeTotpCode(code); if(clean.length!==TOTP_DIGITS) return false;
  for(let step=-TOTP_ALLOWED_DRIFT_STEPS;step<=TOTP_ALLOWED_DRIFT_STEPS;step++){
    if(await totpAt(secretBase32,timeMs+(step*TOTP_PERIOD_SECONDS*1000))===clean) return true;
  }
  return false;
}
function generateTotpSecret(){ return base32Encode(randomBytes(TOTP_SECRET_BYTES)); }
function recoveryChunk(){
  const a=randomBytes(16); let out='';
  for(let i=0;i<16;i++) out+=BASE32_ALPHABET[a[i]&31];
  wipe(a); return `${out.slice(0,4)}-${out.slice(4,8)}-${out.slice(8,12)}-${out.slice(12,16)}`;
}
function generateRecoveryCodes(){
  const codes=new Set(); while(codes.size<RECOVERY_CODE_COUNT) codes.add(recoveryChunk()); return [...codes];
}
async function recoveryHashes(codes){ return Promise.all(codes.map(c=>sha256Text(`safebase-recovery-v1:${normalizeRecoveryCode(c)}`))); }
async function findRecoveryCodeIndex(twoFactor,code){
  const normalized=normalizeRecoveryCode(code); if(normalized.length<12) return -1;
  const hash=await sha256Text(`safebase-recovery-v1:${normalized}`);
  return (twoFactor?.recoveryCodeHashes||[]).findIndex(x=>x===hash);
}
function currentTwoFactor(){ return sessionVault?.settings?.twoFactor || null; }
function pendingTwoFactor(){ return pendingSessionVault?.settings?.twoFactor || null; }
function isTwoFactorEnabled(vault){ return !!vault?.settings?.twoFactor?.enabled && !!vault?.settings?.twoFactor?.secret; }
function clearPendingSession(){ clearTimeout(pendingTwoFactorTimer); pendingTwoFactorTimer=null; pendingTwoFactorExpiresAt=0; pendingSessionKey=null; pendingSessionVault=null; twoFactorFailures=0; twoFactorBlockedUntil=0; }
function expirePendingSecondFactor(){
  if(!pendingSessionVault) return; clearPendingSession(); $('twoFactorView').classList.add('hidden'); unlockView.classList.remove('hidden'); statusText.textContent='Gesperrt'; toast('2FA-Sitzung abgelaufen • Master-PIN erneut eingeben');
}
async function persistVaultWithKey(key,vault){
  const encrypted=await encryptJSON(vault,key,AAD.vault); const meta=await idbGet('meta',META_KEY);
  if(!isV3Meta(meta)) throw new Error('Tresorformat veraltet'); meta.vault=encrypted; await idbPut('meta',meta,META_KEY);
}
function beginSecondFactor(key,vault){
  pendingSessionKey=key; pendingSessionVault=vault; twoFactorFailures=0; twoFactorBlockedUntil=0; pendingTwoFactorExpiresAt=Date.now()+TWO_FACTOR_PENDING_TTL_MS; clearTimeout(pendingTwoFactorTimer); pendingTwoFactorTimer=setTimeout(expirePendingSecondFactor,TWO_FACTOR_PENDING_TTL_MS);
  unlockView.classList.add('hidden'); pinMigrationView?.classList.add('hidden'); setupView.classList.add('hidden'); vaultView.classList.add('hidden'); $('twoFactorView').classList.remove('hidden');
  lockBtn.classList.add('hidden'); statusText.textContent='2FA erforderlich'; $('twoFactorCode').value=''; $('twoFactorCode').focus();
}
function completePendingSession(){
  if(!pendingSessionKey||!pendingSessionVault) throw new Error('Keine 2FA-Sitzung');
  sessionKey=pendingSessionKey; sessionVault=pendingSessionVault; clearPendingSession(); $('twoFactorView').classList.add('hidden'); showVault();
}
function registerTwoFactorFailure(){
  twoFactorFailures++;
  if(twoFactorFailures>=TOTP_MAX_FAILURES){ twoFactorFailures=0; twoFactorBlockedUntil=Date.now()+TOTP_LOCKOUT_MS; toast('Zu viele Versuche • 30 Sekunden warten'); }
  else toast('2FA-Code ist ungültig');
}
async function verifyPendingSecondFactor(input,useRecovery=false){
  if(pendingTwoFactorExpiresAt && Date.now()>pendingTwoFactorExpiresAt){ expirePendingSecondFactor(); return; }
  if(Date.now()<twoFactorBlockedUntil){ toast(`Bitte noch ${Math.ceil((twoFactorBlockedUntil-Date.now())/1000)} Sekunden warten`); return; }
  const tf=pendingTwoFactor(); if(!tf?.enabled) throw new Error('2FA nicht aktiv');
  let ok=false;
  if(useRecovery){
    const idx=await findRecoveryCodeIndex(tf,input);
    if(idx>=0){ tf.recoveryCodeHashes.splice(idx,1); pendingSessionVault.updatedAt=nowISO(); await persistVaultWithKey(pendingSessionKey,pendingSessionVault); ok=true; toast('Recovery-Code verwendet und entwertet'); }
  }else ok=await verifyTotp(tf.secret,input);
  if(!ok){ registerTwoFactorFailure(); return; }
  completePendingSession();
}
async function verifyMasterPinOnly(pin){
  const meta=await idbGet('meta',META_KEY); if(!isV3Meta(meta)) return false;
  if(!isPinMeta(meta) || !isValidPin(pin)) return false;
  try{ const u=await unwrapV3DataKey(meta,pin); wipe(u.rawKey); return true; }catch{return false;}
}
async function verifyActiveFactor(input){
  const tf=currentTwoFactor(); if(!tf?.enabled) return true;
  if(/^\s*\d{6}\s*$/.test(input)) return verifyTotp(tf.secret,input);
  return (await findRecoveryCodeIndex(tf,input))>=0;
}
function renderTwoFactorStatus(){
  const tf=currentTwoFactor(); const enabled=!!tf?.enabled;
  const status=$('twoFactorStatus'); if(status) status.textContent=enabled?`Aktiv • TOTP • ${tf.recoveryCodeHashes?.length||0} Recovery-Codes verfügbar`:'Nicht aktiviert';
  $('enable2FABtn')?.classList.toggle('hidden',enabled); $('disable2FABtn')?.classList.toggle('hidden',!enabled); $('regenerateRecoveryBtn')?.classList.toggle('hidden',!enabled);
}
function showRecoveryCodes(codes){
  $('recoveryCodesText').value=codes.join('\n'); $('recoveryCodesDialog').showModal();
}
function openEnableTwoFactor(){
  pendingTwoFactorSecret=generateTotpSecret(); pendingRecoveryCodes=generateRecoveryCodes(); twoFactorSetupActive=true; clearTimeout(twoFactorSetupTimer);
  twoFactorSetupTimer=setTimeout(()=>{ if(twoFactorSetupActive){ clearTwoFactorSetup(); if(sessionVault) lockVault(); } },TWO_FACTOR_SETUP_TTL_MS);
  $('twoFactorSetupForm').reset(); $('twoFactorSecretDisplay').textContent=pendingTwoFactorSecret; $('twoFactorSetupDialog').showModal();
}
function clearTwoFactorSetup(){ clearTimeout(twoFactorSetupTimer); twoFactorSetupTimer=null; twoFactorSetupActive=false; pendingTwoFactorSecret=null; pendingRecoveryCodes=null; $('twoFactorSecretDisplay').textContent=''; }
async function enableTwoFactor(masterPin,code){
  if(!pendingTwoFactorSecret||!pendingRecoveryCodes) throw new Error('2FA-Einrichtung abgelaufen');
  if(!(await verifyMasterPinOnly(masterPin))) throw new Error('Master-PIN falsch');
  if(!(await verifyTotp(pendingTwoFactorSecret,code))) throw new Error('Authenticator-Code falsch');
  const hashes=await recoveryHashes(pendingRecoveryCodes);
  sessionVault.settings=sessionVault.settings||{};
  sessionVault.settings.twoFactor={enabled:true,method:'totp',algorithm:'SHA-1',digits:TOTP_DIGITS,period:TOTP_PERIOD_SECONDS,secret:pendingTwoFactorSecret,recoveryCodeHashes:hashes,enabledAt:nowISO()};
  const codes=[...pendingRecoveryCodes]; await saveVault(); clearTwoFactorSetup(); toast('Zwei-Faktor-Authentifizierung aktiviert'); return codes;
}
async function disableTwoFactor(masterPin,factor){
  if(!(await verifyMasterPinOnly(masterPin))) throw new Error('Master-PIN falsch');
  if(!(await verifyActiveFactor(factor))) throw new Error('2FA-Code falsch');
  sessionVault.settings.twoFactor={enabled:false}; await saveVault(); toast('2FA deaktiviert');
}
async function regenerateRecoveryCodes(masterPin,factor){
  if(!(await verifyMasterPinOnly(masterPin))) throw new Error('Master-PIN falsch');
  if(!(await verifyActiveFactor(factor))) throw new Error('2FA-Code falsch');
  const codes=generateRecoveryCodes(); sessionVault.settings.twoFactor.recoveryCodeHashes=await recoveryHashes(codes); sessionVault.settings.twoFactor.recoveryUpdatedAt=nowISO(); await saveVault(); showRecoveryCodes(codes); toast('Neue Recovery-Codes erstellt');
}

function requestBackupCredential(pinMode){
  return new Promise(resolve=>{
    const dialog=$('backupCredentialDialog'),form=$('backupCredentialForm'),input=$('backupCredentialInput');
    if(!dialog||!form||!input){ resolve(null); return; }
    if(backupCredentialResolver){ backupCredentialResolver(null); backupCredentialResolver=null; }
    backupCredentialResolver=resolve;
    backupCredentialPinMode=!!pinMode;
    form.reset();
    $('backupCredentialTitle').textContent=pinMode?'Altes Backup: PIN eingeben':'Altes Backup: Passwort eingeben';
    $('backupCredentialHint').textContent=pinMode
      ?'Dieses ältere .json-Backup ist noch mit seiner 6-stelligen Master-PIN geschützt. Gib sie einmalig für den Import ein.'
      :'Dieses ältere .json-Backup ist noch mit seinem bisherigen Master-Passwort geschützt. Gib es einmalig für den Import ein.';
    input.inputMode=pinMode?'numeric':'text';
    input.maxLength=pinMode?6:256;
    input.minLength=pinMode?6:1;
    input.pattern=pinMode?'[0-9]{6}':'';
    dialog.showModal();
    setTimeout(()=>input.focus(),0);
  });
}

function defaultBackupLabel(){
  const d=new Date();
  const pad=n=>String(n).padStart(2,'0');
  return `SafeBase-Backup-${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
}
function backupFilenameFromLabel(label){
  const clean=sanitizeExternalVaultLabel(label)||defaultBackupLabel();
  return `${clean}.safebasebackup`;
}
function requestBackupPasskeyLabel(){
  return new Promise(resolve=>{
    const dialog=$('backupPasskeyNameDialog'),input=$('backupPasskeyNameInput');
    if(!dialog||!input){ resolve(defaultBackupLabel()); return; }
    if(backupPasskeyNameResolver){ backupPasskeyNameResolver(null); backupPasskeyNameResolver=null; }
    backupPasskeyNameResolver=resolve;
    input.value=defaultBackupLabel();
    dialog.showModal();
    setTimeout(()=>{input.focus();input.select();},0);
  });
}
function requestBackupRestorePin(){
  return new Promise(resolve=>{
    const dialog=$('backupRestorePinDialog'),form=$('backupRestorePinForm');
    if(!dialog||!form){resolve(null);return;}
    if(backupRestorePinResolver){backupRestorePinResolver(null);backupRestorePinResolver=null;}
    backupRestorePinResolver=resolve;
    form.reset();
    dialog.showModal();
    setTimeout(()=>$('backupRestorePin')?.focus(),0);
  });
}

function backupCheckMagic(bytes){
  if(!(bytes instanceof Uint8Array)||bytes.length<4) return false;
  for(let i=0;i<4;i++) if(bytes[i]!==BACKUP_MAGIC[i]) return false;
  return true;
}
function backupHeaderBytes({kdfSalt,payloadIv,payloadLength,credentialId,prfSalt,rpId,passkeyLabel,exportedAt}){
  if(!(kdfSalt instanceof Uint8Array)||kdfSalt.length!==32) throw new Error('Ungültiger Backup-KDF-Salt');
  if(!(payloadIv instanceof Uint8Array)||payloadIv.length!==12) throw new Error('Ungültiger Backup-IV');
  if(!(credentialId instanceof Uint8Array)||!credentialId.length||credentialId.length>1024) throw new Error('Ungültige Passkey-ID');
  if(!(prfSalt instanceof Uint8Array)||prfSalt.length!==32) throw new Error('Ungültiger Passkey-Salt');
  if(!Number.isInteger(payloadLength)||payloadLength<16||payloadLength>BACKUP_MAX_BYTES+16) throw new Error('Ungültige Backup-Größe');
  const meta={
    format:'SafeBasePasskeyBackupHeader',version:BACKUP_VERSION,
    kdf:{name:'HKDF',hash:'SHA-256',salt:b64(kdfSalt),info:BACKUP_HKDF_INFO},
    payload:{iv:b64(payloadIv),length:payloadLength,aad:BACKUP_AAD},
    webauthn:{type:'public-key',credentialId:b64(credentialId),prfSalt:b64(prfSalt),rpId:safeText(rpId||location.hostname),label:safeText(passkeyLabel||'').slice(0,64)},
    appVersion:APP_VERSION,exportedAt:safeText(exportedAt||nowISO())
  };
  const metaBytes=enc.encode(JSON.stringify(meta));
  if(metaBytes.length>8192) throw new Error('Backup-Header ist zu groß');
  const prefix=new Uint8Array(9); prefix.set(BACKUP_MAGIC,0); prefix[4]=BACKUP_VERSION; prefix.set(externalU32(metaBytes.length),5);
  return externalConcat(prefix,metaBytes);
}
async function readPasskeyBackupHeader(file){
  if(!file||file.size<9) throw new Error('Backup-Datei zu kurz');
  const first=new Uint8Array(await file.slice(0,9).arrayBuffer());
  if(!backupCheckMagic(first)) throw new Error('Keine SafeBase-Passkey-Backup-Datei');
  const version=first[4];
  if(version!==BACKUP_VERSION) throw new Error('Nicht unterstützte Backup-Version');
  const metaLength=new DataView(first.buffer,first.byteOffset,first.byteLength).getUint32(5,false);
  if(metaLength<80||metaLength>8192||9+metaLength>file.size) throw new Error('Ungültiger Backup-Header');
  let meta;
  try{meta=JSON.parse(dec.decode(new Uint8Array(await file.slice(9,9+metaLength).arrayBuffer())));}catch{throw new Error('Beschädigter Backup-Header');}
  if(meta?.format!=='SafeBasePasskeyBackupHeader'||meta?.version!==version) throw new Error('Ungültiger Backup-Header');
  if(meta?.kdf?.name!=='HKDF'||meta?.kdf?.hash!=='SHA-256'||safeText(meta?.kdf?.info)!==BACKUP_HKDF_INFO) throw new Error('Nicht unterstützte Backup-Schlüsselableitung');
  if(safeText(meta?.payload?.aad)!==BACKUP_AAD) throw new Error('Ungültige Backup-Authentifizierung');
  const kdfSalt=unb64(meta.kdf.salt),payloadIv=unb64(meta.payload.iv),credentialId=unb64(meta.webauthn?.credentialId),prfSalt=unb64(meta.webauthn?.prfSalt);
  const rpId=safeText(meta.webauthn?.rpId||''),passkeyLabel=safeText(meta.webauthn?.label||'').slice(0,64),payloadLength=Number(meta.payload.length);
  if(kdfSalt.length!==32||payloadIv.length!==12||prfSalt.length!==32||!credentialId.length||credentialId.length>1024||!rpId) throw new Error('Ungültige Backup-Schlüsseldaten');
  if(rpId!==location.hostname) throw new Error(`Dieses Backup ist an ${rpId} gebunden. Öffne SafeBase unter genau dieser Webadresse.`);
  if(!Number.isInteger(payloadLength)||payloadLength<16||payloadLength>BACKUP_MAX_BYTES+16) throw new Error('Ungültige Backup-Größe');
  const headerLength=9+metaLength;
  if(headerLength+payloadLength!==file.size) throw new Error('Backup-Datei ist unvollständig oder enthält Zusatzdaten');
  return {version,headerLength,kdfSalt,payloadIv,payloadLength,credentialId,prfSalt,rpId,passkeyLabel};
}
async function deriveBackupKey(prfSecret,kdfSalt){
  if(!(prfSecret instanceof Uint8Array)||prfSecret.length!==32) throw new Error('Ungültiger Sicherheitsschlüssel');
  if(!(kdfSalt instanceof Uint8Array)||kdfSalt.length!==32) throw new Error('Ungültiger Backup-KDF-Salt');
  const material=await crypto.subtle.importKey('raw',prfSecret,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:kdfSalt,info:enc.encode(BACKUP_HKDF_INFO)},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function validatePasskeyBackupPayload(payload){
  if(!payload||payload.format!=='SafeBasePasskeyBackup'||payload.version!==BACKUP_VERSION||!payload.vault) throw new Error('Ungültiger Backup-Inhalt');
  const vault=payload.vault;
  if(!Array.isArray(vault.passwords)||!Array.isArray(vault.notes)||vault.passwords.length>10000||vault.notes.length>10000) throw new Error('Ungültige Backup-Tresordaten');
  if(!vault.settings||typeof vault.settings!=='object') vault.settings={autoLockMinutes:5,twoFactor:{enabled:false}};
  return vault;
}
async function buildPasskeyBackupFile(label){
  if(!sessionVault) throw new Error('Tresor ist gesperrt');
  const cleanLabel=sanitizeExternalVaultLabel(label)||defaultBackupLabel();
  const prfSalt=randomBytes(32),kdfSalt=randomBytes(32);
  toast(`Backup-Passkey „${cleanLabel}“ jetzt einrichten`);
  const registered=await externalCreatePasskey(prfSalt,cleanLabel);
  let prfSecret=registered.prfSecret,key,payloadBytes;
  try{
    key=await deriveBackupKey(prfSecret,kdfSalt);
    const payload={format:'SafeBasePasskeyBackup',version:BACKUP_VERSION,crypto:{cipher:'AES-256-GCM',keyProtection:'WebAuthn-PRF-only',kdf:'HKDF-SHA-256'},appVersion:APP_VERSION,exportedAt:nowISO(),vault:sessionVault};
    payloadBytes=enc.encode(JSON.stringify(payload));
    if(payloadBytes.length>BACKUP_MAX_BYTES) throw new Error('Backup ist zu groß');
    const payloadIv=randomBytes(12);
    const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:payloadIv,tagLength:128,additionalData:enc.encode(BACKUP_AAD)},key,payloadBytes));
    const header=backupHeaderBytes({kdfSalt,payloadIv,payloadLength:cipher.length,credentialId:registered.credentialId,prfSalt,rpId:location.hostname,passkeyLabel:registered.passkeyLabel,exportedAt:payload.exportedAt});
    const fileObj=new File([header,cipher],backupFilenameFromLabel(registered.passkeyLabel),{type:'application/octet-stream'});
    return {fileObj,passkeyLabel:registered.passkeyLabel};
  }finally{
    wipe(prfSecret); if(payloadBytes)wipe(payloadBytes); wipe(prfSalt); wipe(kdfSalt);
  }
}
function backupIsMobileDevice(){
  const ua=navigator.userAgent||'';
  if(navigator.userAgentData?.mobile===true) return true;
  return /Android|iPhone|iPad|iPod|Mobile/i.test(ua) || (navigator.platform==='MacIntel' && navigator.maxTouchPoints>1);
}
function backupDeviceLabel(){
  const ua=navigator.userAgent||'';
  if(/iPhone|iPad|iPod/i.test(ua) || (navigator.platform==='MacIntel' && navigator.maxTouchPoints>1)) return 'iPhone/iPad';
  if(/Android/i.test(ua)) return 'Android';
  if(/Macintosh|Mac OS X/i.test(ua)) return 'Mac';
  if(/Windows/i.test(ua)) return 'Windows-PC';
  if(/Linux/i.test(ua)) return 'PC/Linux';
  return 'dieses Gerät';
}
function downloadPasskeyBackupFile(fileObj){
  const url=URL.createObjectURL(fileObj);
  const a=document.createElement('a');
  a.href=url; a.download=fileObj.name; a.rel='noopener';
  a.style.display='none';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),60000);
  return true;
}
function canShareBackupFile(fileObj){
  try{return !!(navigator.share && navigator.canShare?.({files:[fileObj]}));}catch{return false;}
}
async function savePasskeyBackupFile(fileObj,{forceDownload=false}={}){
  systemPickerActive=true; clearTimeout(autoLockTimer);
  try{
    if(forceDownload){
      downloadPasskeyBackupFile(fileObj);
      toast('Verschlüsselte Backup-Datei wird heruntergeladen');
      return {ok:true,method:'download'};
    }

    const mobile=backupIsMobileDevice();

    // iPhone/iPad/Android: the native share sheet is the most reliable way to
    // hand the encrypted file to Files/Downloads/cloud storage from a PWA.
    if(mobile && canShareBackupFile(fileObj)){
      try{
        await navigator.share({files:[fileObj],title:'SafeBase Passkey-Backup',text:'Verschlüsselte SafeBase-Backup-Datei'});
        toast('Datei über das Teilen-Menü übergeben');
        return {ok:true,method:'share'};
      }catch(e){
        if(e?.name==='AbortError') return {ok:false,aborted:true,method:'share'};
        // Continue to the normal browser download as fallback.
      }
    }

    // Chrome/Edge and other browsers with File System Access: give desktop
    // users a real Save As dialog. This is deliberately called from a click.
    if(!mobile && typeof window.showSaveFilePicker==='function'){
      try{
        const handle=await window.showSaveFilePicker({suggestedName:fileObj.name,types:[{description:'SafeBase Passkey-Backup',accept:{'application/octet-stream':['.safebasebackup']}}]});
        const writable=await handle.createWritable(); await writable.write(fileObj); await writable.close();
        toast('Verschlüsselte Backup-Datei gespeichert');
        return {ok:true,method:'picker'};
      }catch(e){
        if(e?.name==='AbortError') return {ok:false,aborted:true,method:'picker'};
        // Safari/Firefox/permission errors fall through to direct download.
      }
    }

    // macOS Safari/Firefox, Windows Firefox and mobile browsers without file
    // sharing: standards-based direct download from the explicit user click.
    downloadPasskeyBackupFile(fileObj);
    toast('Verschlüsselte Backup-Datei wird heruntergeladen');
    return {ok:true,method:'download'};
  }finally{systemPickerActive=false;if(sessionVault)resetAutoLock();}
}
function updateBackupSaveDialog(){
  const dialog=$('backupSaveDialog');
  if(!dialog || !pendingPasskeyBackupFile)return;
  const name=$('backupSaveFileName'); if(name)name.textContent=pendingPasskeyBackupFile.name;
  const hint=$('backupSaveDeviceHint');
  if(hint){
    const device=backupDeviceLabel();
    hint.textContent=backupIsMobileDevice()
      ? `${device}: „Auf Gerät speichern / teilen“ öffnet das Teilen-Menü. Wähle dort „In Dateien sichern“, „Downloads“ oder deinen gewünschten Speicherort.`
      : `${device}: „Auf Gerät speichern“ öffnet – je nach Browser – „Speichern unter“ oder startet einen normalen Download.`;
  }
  const primary=$('backupSaveNowBtn'); if(primary)primary.textContent=backupIsMobileDevice()?'Auf Gerät speichern / teilen':'Auf Gerät speichern';
}
function showBackupSaveDialog(){
  const dialog=$('backupSaveDialog');
  if(!dialog || !pendingPasskeyBackupFile)return;
  updateBackupSaveDialog();
  if(!dialog.open)dialog.showModal();
}
async function finishBackupSave({forceDownload=false,closeOnSuccess=true}={}){
  if(!pendingPasskeyBackupFile)return toast('Keine wartende Backup-Datei vorhanden');
  const primary=$('backupSaveNowBtn'), direct=$('backupDirectDownloadBtn'), retry=$('retryBackupSaveBtn');
  [primary,direct,retry].forEach(b=>{if(b)b.disabled=true;});
  try{
    const result=await savePasskeyBackupFile(pendingPasskeyBackupFile,{forceDownload});
    if(!result?.ok){
      setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ ist vorhanden. ⚠ Die verschlüsselte Datei wurde noch nicht gespeichert.`, 'warning');
      return false;
    }
    const methodText=result.method==='share'?'über das Teilen-Menü übergeben':result.method==='picker'?'gespeichert':'heruntergeladen';
    setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ + ✓ Datei „${pendingPasskeyBackupFile.name}“ (${methodText}). Für die Wiederherstellung brauchst du beides.`, 'success');
    if(retry)retry.textContent='Verschlüsselte Datei erneut speichern';
    if(closeOnSuccess && $('backupSaveDialog')?.open)$('backupSaveDialog').close();
    return true;
  }catch(err){
    toast(err?.message||'Backup-Datei konnte nicht gespeichert werden');
    setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ ist vorhanden. ⚠ Speichern der Datei fehlgeschlagen – bitte erneut versuchen.`, 'warning');
    return false;
  }finally{[primary,direct,retry].forEach(b=>{if(b)b.disabled=false;});}
}
async function retryPendingBackupSave(){
  if(!pendingPasskeyBackupFile)return toast('Keine wartende Backup-Datei vorhanden');
  showBackupSaveDialog();
}

function validateEncryptedPayload(p){ return !!p && typeof p.iv==='string' && typeof p.data==='string' && p.iv.length<128 && p.data.length>0; }
function validateBackupStructure(backup){
  if(!backup || backup.format!=='SafeBaseBackup' || !backup.meta) throw new Error('Ungültiges Legacy-Backup');
  if(Array.isArray(backup.files) && backup.files.length) throw new Error('Dieses Backup enthält alte lokale Dateianhänge. SafeBase speichert Fotos/Dokumente separat als .safebase-Datei.');
  if(!validateEncryptedPayload(backup.meta.verifier) || !validateEncryptedPayload(backup.meta.vault)) throw new Error('Ungültige Tresordaten');
  kdfParams(backup.meta);
}
async function validateBackupCryptographically(backup,password){
  if(isV3Meta(backup.meta)){
    const unlocked=await unwrapV3DataKey(backup.meta,password);
    try{ await decryptJSON(backup.meta.vault,unlocked.dataKey,AAD.vault); }
    finally{ wipe(unlocked.rawKey); }
  }else{
    const {salt,iterations}=kdfParams(backup.meta);
    const oldKey=await deriveKey(password,salt,iterations);
    const check=await decryptJSON(backup.meta.verifier,oldKey); if(!check?.ok) throw new Error('Backup-Passwort falsch');
    await decryptJSON(backup.meta.vault,oldKey);
  }
}
function setBackupPairStatus(message,state='info'){
  const el=$('backupPairStatus');
  if(!el)return;
  el.textContent=message;
  el.dataset.state=state;
}
function updateBackupRetryButton(show){
  const btn=$('retryBackupSaveBtn');
  if(btn)btn.classList.toggle('hidden',!show);
}
async function retryPendingBackupSave(){
  if(!pendingPasskeyBackupFile)return toast('Keine wartende Backup-Datei vorhanden');
  const btn=$('retryBackupSaveBtn'); if(btn)btn.disabled=true;
  try{
    const saved=await savePasskeyBackupFile(pendingPasskeyBackupFile);
    if(!saved){
      setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ ist vorhanden. ⚠ Die verschlüsselte Datei wurde noch nicht gespeichert.`, 'warning');
      return;
    }
    setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ + ✓ Datei „${pendingPasskeyBackupFile.name}“. Für die Wiederherstellung brauchst du beides.`, 'success');
    if(btn)btn.textContent='Verschlüsselte Datei erneut speichern';
    // Keep the already encrypted File in memory until lock/reload so the user can
    // explicitly save another copy without creating another passkey.
  }catch(err){toast(err?.message||'Backup-Datei konnte nicht gespeichert werden');}
  finally{if(btn)btn.disabled=false;}
}
async function exportBackup(){
  const btn=$('exportBtn'); if(btn)btn.disabled=true;
  try{
    const label=await requestBackupPasskeyLabel();
    if(!label)return;
    setBackupPairStatus('Schritt 1/2: Passkey wird erstellt …','info');
    const bundle=await buildPasskeyBackupFile(label);
    pendingPasskeyBackupFile=bundle.fileObj; pendingPasskeyBackupLabel=bundle.passkeyLabel;
    const saveBtn=$('retryBackupSaveBtn');
    if(saveBtn)saveBtn.textContent='Verschlüsselte Datei speichern / teilen';
    updateBackupRetryButton(true);
    setBackupPairStatus(`✓ Schritt 1/2: Passkey „${bundle.passkeyLabel}“ ist erstellt. Schritt 2/2: Speichere jetzt die verschlüsselte Datei „${bundle.fileObj.name}“.`, 'warning');
    toast('Passkey erstellt • jetzt die verschlüsselte Datei speichern');
    showBackupSaveDialog();
  }catch(err){
    setBackupPairStatus('Backup wurde nicht vollständig erstellt.','warning');
    toast(err?.message||'Passkey-Backup konnte nicht erstellt werden');
  }
  finally{if(btn)btn.disabled=false;}
}
async function importPasskeyBackup(file){
  const head=await readPasskeyBackupHeader(file);
  toast(`Backup-Passkey${head.passkeyLabel?` „${head.passkeyLabel}“`:''} jetzt bestätigen`);
  const prfSecret=await externalGetPasskeyPrf(head.credentialId,head.prfSalt); let key,plainBytes,payload;
  try{
    key=await deriveBackupKey(prfSecret,head.kdfSalt);
    const cipher=new Uint8Array(await file.slice(head.headerLength,head.headerLength+head.payloadLength).arrayBuffer());
    try{plainBytes=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:head.payloadIv,tagLength:128,additionalData:enc.encode(BACKUP_AAD)},key,cipher));}
    catch{throw new Error('Falscher Passkey/Sicherheitsschlüssel oder beschädigtes Backup');}
    try{payload=JSON.parse(dec.decode(plainBytes));}catch{throw new Error('Beschädigter Backup-Inhalt');}
    const restoredVault=validatePasskeyBackupPayload(payload);
    if(!confirm('Passkey-Backup wurde erfolgreich entschlüsselt und geprüft. Vorhandenen lokalen Tresor jetzt vollständig ersetzen?')) return;
    const newPin=await requestBackupRestorePin();
    if(newPin===null)return;
    const raw=randomBytes(32); let dataKey;
    try{
      dataKey=await importDataKey(raw);
      const vault={...restoredVault,version:APP_VERSION,updatedAt:nowISO()};
      const meta=await createV3Meta(newPin,raw,dataKey,vault,AUTH_MODE_PIN6);
      await atomicReplace(meta,[]); await idbClear('stagingFiles'); clearPinFailures();
    }finally{wipe(raw);}
    toast('Passkey-Backup wiederhergestellt • neue Master-PIN ist aktiv');
    setTimeout(()=>location.reload(),350);
  }finally{wipe(prfSecret);if(plainBytes)wipe(plainBytes);}
}
async function importLegacyBackup(file){
  const text=await file.text();
  const backup=JSON.parse(text); validateBackupStructure(backup);
  const pinBackup=isPinMeta(backup.meta);
  const credential=await requestBackupCredential(pinBackup);
  if(credential===null)return;
  if(pinBackup&&!isValidPin(credential)) throw new Error('Backup-PIN muss genau 6 Ziffern haben');
  await validateBackupCryptographically(backup,credential);
  if(!confirm('Älteres .json-Backup wurde erfolgreich geprüft. Vorhandenen lokalen Tresor jetzt vollständig ersetzen?')) return;
  await atomicReplace(backup.meta,[]); await idbClear('stagingFiles');
  toast('Legacy-Backup sicher importiert'); setTimeout(()=>location.reload(),250);
}
async function importBackup(file){
  if(!file) return;
  const first=new Uint8Array(await file.slice(0,9).arrayBuffer());
  if(backupCheckMagic(first)) return importPasskeyBackup(file);
  return importLegacyBackup(file);
}

async function changeMasterPin(currentPin,newPin){
  if(!isValidPin(currentPin) || !isValidPin(newPin)) throw new Error('PIN muss genau 6 Ziffern haben');
  const meta=await idbGet('meta',META_KEY);
  if(!isV3Meta(meta) || !isPinMeta(meta)) throw new Error('Tresorformat veraltet');
  const oldParams=kdfParams(meta);
  const oldKek=await deriveKey(currentPin,oldParams.salt,oldParams.iterations);
  const raw=await decryptBytes(meta.wrappedKey,oldKek,AAD.wrappedKey);
  try{
    const dataKey=await importDataKey(raw); await decryptJSON(meta.verifier,dataKey,AAD.verifier);
    const salt=randomBytes(32); const newKek=await deriveKey(newPin,salt,PBKDF2_ITERATIONS);
    const updated={...meta,
      version:APP_VERSION,schemaVersion:CRYPTO_SCHEMA_VERSION,authMode:AUTH_MODE_PIN6,
      salt:b64(salt),iterations:PBKDF2_ITERATIONS,
      kdf:{name:'PBKDF2',hash:'SHA-256',iterations:PBKDF2_ITERATIONS,salt:b64(salt)},
      wrappedKey:await encryptBytes(raw,newKek,AAD.wrappedKey)
    };
    await idbPut('meta',updated,META_KEY);
    toast('Master-PIN geändert');
  } finally { wipe(raw); }
}

async function migrateMasterCredentialToPin(oldCredential,newPin){
  if(!oldCredential) throw new Error('Bisheriges Master-Passwort fehlt');
  if(!isValidPin(newPin)) throw new Error('Neue PIN muss genau 6 Ziffern haben');
  const meta=await idbGet('meta',META_KEY);
  if(!meta) throw new Error('Kein Tresor vorhanden');

  if(isV3Meta(meta)){
    const unlocked=await unwrapV3DataKey(meta,oldCredential);
    try{
      await decryptJSON(meta.vault,unlocked.dataKey,AAD.vault);
      const salt=randomBytes(32);
      const newKek=await deriveKey(newPin,salt,PBKDF2_ITERATIONS);
      const updated={...meta,version:APP_VERSION,schemaVersion:CRYPTO_SCHEMA_VERSION,authMode:AUTH_MODE_PIN6,
        salt:b64(salt),iterations:PBKDF2_ITERATIONS,
        kdf:{name:'PBKDF2',hash:'SHA-256',iterations:PBKDF2_ITERATIONS,salt:b64(salt)},
        wrappedKey:await encryptBytes(unlocked.rawKey,newKek,AAD.wrappedKey)};
      await idbPut('meta',updated,META_KEY);
    } finally { wipe(unlocked.rawKey); }
    return;
  }

  const {salt,iterations}=kdfParams(meta);
  const legacyKey=await deriveKey(oldCredential,salt,iterations);
  const check=await decryptJSON(meta.verifier,legacyKey);
  if(!check?.ok) throw new Error('Bisheriges Master-Passwort falsch');
  const legacyVault=await decryptJSON(meta.vault,legacyKey);
  const raw=randomBytes(32);
  try{
    const dataKey=await importDataKey(raw);
    const upgradedVault={...legacyVault,version:APP_VERSION};
    const upgradedMeta=await createV3Meta(newPin,raw,dataKey,upgradedVault,AUTH_MODE_PIN6);
    await atomicReplace(upgradedMeta,[]);
    await idbClear('stagingFiles');
  } finally { wipe(raw); }
}

async function requestPersistentStorage(){
  try{ if(navigator.storage?.persist) await navigator.storage.persist(); }catch{}
}

function setupEvents(){
  // Abbrechen darf nie durch HTML-Formularvalidierung blockiert werden.
  // Deshalb sind die Buttons type=button und schließen ihren Dialog explizit.
  document.querySelectorAll('dialog button[value="cancel"]').forEach(btn=>{
    btn.addEventListener('click',e=>{
      e.preventDefault();
      const dialog=btn.closest('dialog');
      if(dialog?.open) dialog.close('cancel');
    });
  });

  const pinFieldIds=['setupPassword','setupPassword2','unlockPassword','legacyNewPin','legacyNewPin2','currentPassword','newPassword','newPassword2','twoFactorSetupPassword','twoFactorManagePassword','backupRestorePin','backupRestorePin2'];
  pinFieldIds.forEach(id=>$(id)?.addEventListener('input',e=>{ e.target.value=normalizePin(e.target.value); }));

  $('setupBtn').addEventListener('click',async()=>{
    const a=normalizePin($('setupPassword').value),b=normalizePin($('setupPassword2').value);
    if(!isValidPin(a))return toast('Die Master-PIN muss genau 6 Ziffern haben');
    if(a!==b)return toast('PINs stimmen nicht überein');
    $('setupPassword').value=$('setupPassword2').value='';
    try{await setupVault(a);clearPinFailures();}catch{toast('Tresor konnte nicht erstellt werden');}
  });
  $('unlockBtn').addEventListener('click',async()=>{
    if(Date.now()<pinBlockedUntil){toast(`Zu viele Versuche • bitte noch ${Math.ceil((pinBlockedUntil-Date.now())/1000)} Sekunden warten`);return;}
    const pin=normalizePin($('unlockPassword').value); $('unlockPassword').value='';
    if(!isValidPin(pin))return toast('Bitte genau 6 Ziffern eingeben');
    try{await unlockVault(pin);clearPinFailures();}catch{registerPinFailure();toast('Falsche PIN oder beschädigte Daten');}
  });
  $('unlockPassword').addEventListener('keydown',e=>{if(e.key==='Enter')$('unlockBtn').click();});
  $('migratePinBtn').addEventListener('click',async()=>{
    const oldCredential=$('legacyMasterPassword').value;
    const a=normalizePin($('legacyNewPin').value),b=normalizePin($('legacyNewPin2').value);
    if(!oldCredential)return toast('Bisheriges Master-Passwort eingeben');
    if(!isValidPin(a))return toast('Die neue PIN muss genau 6 Ziffern haben');
    if(a!==b)return toast('PINs stimmen nicht überein');
    const btn=$('migratePinBtn'); btn.disabled=true;
    try{
      await migrateMasterCredentialToPin(oldCredential,a);
      $('legacyMasterPassword').value=$('legacyNewPin').value=$('legacyNewPin2').value='';
      toast('PIN aktiviert • ab jetzt nur noch 6 Ziffern');
      setTimeout(()=>location.reload(),350);
    }catch{toast('Altes Master-Passwort falsch oder Daten beschädigt');}
    finally{btn.disabled=false;}
  });
  lockBtn.addEventListener('click',lockVault);
  $('twoFactorCode').addEventListener('input',e=>{ e.target.value=normalizeTotpCode(e.target.value); });
  $('twoFactorCode').addEventListener('keydown',e=>{if(e.key==='Enter')$('verifyTwoFactorBtn').click();});
  $('verifyTwoFactorBtn').addEventListener('click',async()=>{ const c=$('twoFactorCode').value; $('twoFactorCode').value=''; try{await verifyPendingSecondFactor(c,false);}catch{toast('2FA-Prüfung fehlgeschlagen');} });
  $('useRecoveryBtn').addEventListener('click',()=>{ $('twoFactorRecoveryWrap').classList.toggle('hidden'); if(!$('twoFactorRecoveryWrap').classList.contains('hidden')) $('twoFactorRecoveryCode').focus(); });
  $('verifyRecoveryBtn').addEventListener('click',async()=>{ const c=$('twoFactorRecoveryCode').value; $('twoFactorRecoveryCode').value=''; try{await verifyPendingSecondFactor(c,true);}catch{toast('Recovery-Code ungültig');} });
  $('cancelTwoFactorBtn').addEventListener('click',()=>{ clearPendingSession(); $('twoFactorView').classList.add('hidden'); unlockView.classList.remove('hidden'); statusText.textContent='Gesperrt'; });
  const resetLocalVault=async()=>{if(confirm('ACHTUNG: Alle lokalen SafeBase-Daten endgültig löschen? Ein Backup ist danach die einzige Wiederherstellung.')){await idbClear('meta');await idbClear('files');await idbClear('stagingFiles');location.reload();}};
  $('resetBtn').addEventListener('click',resetLocalVault);
  $('migrationResetBtn').addEventListener('click',resetLocalVault);
  document.querySelectorAll('.tab').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.tabpage').forEach(x=>x.classList.add('hidden'));btn.classList.add('active');$(`tab-${btn.dataset.tab}`).classList.remove('hidden');}));
  $('externalVaultNameForm').addEventListener('submit',e=>{
    if(e.submitter?.value==='cancel')return;
    e.preventDefault();
    const label=sanitizeExternalVaultLabel($('externalVaultNameInput').value);
    if(!label)return toast('Bitte einen Namen für Passkey und Tresor eingeben');
    const resolve=externalVaultNameResolver; externalVaultNameResolver=null;
    $('externalVaultNameDialog').close();
    if(resolve)resolve(label);
  });
  $('externalVaultNameDialog').addEventListener('close',()=>{
    if(externalVaultNameResolver){const resolve=externalVaultNameResolver;externalVaultNameResolver=null;resolve(null);}
  });
  $('newExternalVaultBtn').addEventListener('click',beginNewExternalVault);
  bindFilePickerInput('externalVaultInput',async e=>{try{if(e.target.files[0])await chooseExternalVaultFile(e.target.files[0]);}catch(err){toast(err?.message||'Tresordatei konnte nicht geöffnet werden');}});
  bindFilePickerInput('externalAddFilesInput',async e=>{await addExternalFiles(e.target.files);});
  $('saveExternalVaultBtn').addEventListener('click',saveExternalVaultToFiles);
  $('restoreExternalDraftBtn').addEventListener('click',recoverExternalDraft);
  $('discardExternalDraftBtn').addEventListener('click',discardExternalDraft);
  $('closeExternalVaultBtn').addEventListener('click',()=>{if(externalVault?.dirty&&!confirm('Ungespeicherte Änderungen verwerfen und Tresordatei schließen?'))return;clearExternalVault();toast('Tresordatei geschlossen');});
  $('searchExternalFiles').addEventListener('input',renderExternalVault);
  document.querySelectorAll('[data-external-filter]').forEach(btn=>btn.addEventListener('click',()=>{externalListFilter=btn.dataset.externalFilter||'all';renderExternalVault();}));
  $('externalSortSelect').addEventListener('change',e=>{externalListSort=e.target.value||'newest';renderExternalVault();});
  $('externalMenuCancelBtn').addEventListener('click',()=>{$('externalItemMenuDialog').close();});
  $('externalMenuOpenBtn').addEventListener('click',async()=>{const id=externalActionItemId;$('externalItemMenuDialog').close();if(id)await openExternalItem(id);});
  $('externalMenuExportBtn').addEventListener('click',async()=>{const item=selectedExternalItem();$('externalItemMenuDialog').close();if(!item)return;try{await exportDecryptedExternalItem(item);}catch(err){toast(err?.message||'Export nicht möglich');}});
  $('externalMenuRenameBtn').addEventListener('click',()=>{const item=selectedExternalItem();if(!item)return;$('externalRenameInput').value=item.name||'';$('externalItemMenuDialog').close();$('externalRenameDialog').showModal();setTimeout(()=>{$('externalRenameInput').focus();$('externalRenameInput').select();},0);});
  $('externalRenameForm').addEventListener('submit',e=>{if(e.submitter?.value==='cancel')return;e.preventDefault();const item=selectedExternalItem(),name=$('externalRenameInput').value.trim();if(!item||!name)return toast('Dateiname fehlt');item.name=name.slice(0,500);externalVault.updatedAt=nowISO();markExternalVaultDirty();$('externalRenameDialog').close();renderExternalVault();toast('Datei umbenannt • Tresor erneut sichern');});
  $('externalMenuInfoBtn').addEventListener('click',()=>{const item=selectedExternalItem();$('externalItemMenuDialog').close();openExternalInfo(item);});
  $('externalInfoCloseBtn').addEventListener('click',()=>{$('externalInfoDialog').close();});
  $('externalMenuDeleteBtn').addEventListener('click',()=>{const id=externalActionItemId;$('externalItemMenuDialog').close();if(id)deleteExternalItem(id);});

  $('externalVaultPasswordForm').addEventListener('submit',async e=>{if(e.submitter?.value==='cancel')return;e.preventDefault();const pw=$('externalVaultPassword').value,submit=$('externalVaultPasswordSubmit');if(submit)submit.disabled=true;try{if(externalVaultPasswordMode!=='legacy-open')throw new Error('Ungültiger Vorgang');if(pw.length<16)throw new Error('Das alte Tresordatei-Passwort ist zu kurz oder fehlt');await loadLegacyExternalVaultWithPassword(pw);$('externalVaultPasswordForm').reset();$('externalVaultPasswordDialog').close();}catch(err){toast(err?.message||'Ältere Tresordatei konnte nicht entsperrt werden');}finally{if(submit)submit.disabled=false;}});
  $('externalVaultPasswordDialog').addEventListener('close',()=>{$('externalVaultPasswordForm').reset();if(!externalVault){pendingExternalOpenFile=null;pendingExternalOpenHeader=null;}externalVaultPasswordMode=null;});
  $('closeExternalPreviewBtn').addEventListener('click',closeExternalPreview);
  $('externalPreviewDialog').addEventListener('close',closeExternalPreview);
  $('addPasswordBtn').addEventListener('click',()=>openPasswordDialog());$('searchPasswords').addEventListener('input',renderPasswords);
  $('passwordForm').addEventListener('submit',async e=>{if(e.submitter?.value==='cancel')return; e.preventDefault();const id=$('passwordId').value||uuid();const item={id,name:$('entryName').value.trim(),username:$('entryUsername').value.trim(),password:$('entryPassword').value,website:$('entryWebsite').value.trim(),note:$('entryNote').value.trim(),updatedAt:nowISO()};const i=sessionVault.passwords.findIndex(x=>x.id===id);if(i>=0)sessionVault.passwords[i]={...sessionVault.passwords[i],...item};else sessionVault.passwords.push({...item,createdAt:nowISO()});await saveVault();$('passwordForm').reset();$('passwordDialog').close();toast('Gespeichert');});
  $('toggleEntryPassword').addEventListener('click',()=>{
    clearTimeout(passwordRevealTimer);
    const field=$('entryPassword'); field.type=field.type==='password'?'text':'password';
    if(field.type==='text') passwordRevealTimer=setTimeout(()=>{field.type='password';},20000);
  });
  $('addNoteBtn').addEventListener('click',()=>openNoteDialog());$('searchNotes').addEventListener('input',renderNotes);
  $('noteForm').addEventListener('submit',async e=>{if(e.submitter?.value==='cancel')return;e.preventDefault();const id=$('noteId').value||uuid();const item={id,title:$('noteTitle').value.trim(),body:$('noteBody').value,updatedAt:nowISO()};const i=sessionVault.notes.findIndex(x=>x.id===id);if(i>=0)sessionVault.notes[i]={...sessionVault.notes[i],...item};else sessionVault.notes.push({...item,createdAt:nowISO()});await saveVault();$('noteForm').reset();$('noteDialog').close();toast('Gespeichert');});
  $('lengthSlider').addEventListener('input',()=>{$('lengthValue').textContent=$('lengthSlider').value;generatePassword();});['useUpper','useLower','useNumbers','useSymbols'].forEach(id=>$(id).addEventListener('change',generatePassword));$('generateBtn').addEventListener('click',generatePassword);$('copyGeneratedBtn').addEventListener('click',()=>copyText($('generatedPassword').value));
  $('exportBtn').addEventListener('click',exportBackup);
  $('retryBackupSaveBtn')?.addEventListener('click',retryPendingBackupSave);
  $('backupSaveNowBtn')?.addEventListener('click',()=>finishBackupSave());
  $('backupDirectDownloadBtn')?.addEventListener('click',()=>finishBackupSave({forceDownload:true}));
  $('backupSaveLaterBtn')?.addEventListener('click',()=>{$('backupSaveDialog')?.close();setBackupPairStatus(`✓ Passkey „${pendingPasskeyBackupLabel}“ ist vorhanden. ⚠ Die verschlüsselte Datei muss noch gespeichert werden.`, 'warning');});
  bindFilePickerInput('importInput',async e=>{try{if(e.target.files[0])await importBackup(e.target.files[0]);}catch(err){toast(err?.message||'Backup abgelehnt: Passkey, PIN/Passwort, Format oder Daten ungültig');}});

  $('backupPasskeyNameForm').addEventListener('submit',e=>{
    e.preventDefault();
    const label=sanitizeExternalVaultLabel($('backupPasskeyNameInput').value);
    if(!label)return toast('Bitte einen Namen für Passkey und Backup eingeben');
    const resolve=backupPasskeyNameResolver; backupPasskeyNameResolver=null;
    $('backupPasskeyNameDialog').close();
    if(resolve)resolve(label);
  });
  $('backupPasskeyNameDialog').addEventListener('close',()=>{
    $('backupPasskeyNameForm').reset();
    if(backupPasskeyNameResolver){const resolve=backupPasskeyNameResolver;backupPasskeyNameResolver=null;resolve(null);}
  });

  $('backupRestorePinForm').addEventListener('submit',e=>{
    e.preventDefault();
    const a=normalizePin($('backupRestorePin').value),b=normalizePin($('backupRestorePin2').value);
    if(!isValidPin(a))return toast('Neue Master-PIN muss genau 6 Ziffern haben');
    if(a!==b)return toast('PINs stimmen nicht überein');
    const resolve=backupRestorePinResolver; backupRestorePinResolver=null;
    $('backupRestorePinDialog').close();
    if(resolve)resolve(a);
  });
  $('backupRestorePinDialog').addEventListener('close',()=>{
    $('backupRestorePinForm').reset();
    if(backupRestorePinResolver){const resolve=backupRestorePinResolver;backupRestorePinResolver=null;resolve(null);}
  });

  // Nur für ältere .json-Backups: neue Backups verwenden ausschließlich Passkey/WebAuthn-PRF.
  $('backupCredentialInput').addEventListener('input',e=>{if(backupCredentialPinMode)e.target.value=normalizePin(e.target.value);});
  $('backupCredentialForm').addEventListener('submit',e=>{
    e.preventDefault();
    const input=$('backupCredentialInput');
    const value=backupCredentialPinMode?normalizePin(input.value):input.value;
    if(backupCredentialPinMode&&!isValidPin(value))return toast('Backup-PIN muss genau 6 Ziffern haben');
    if(!backupCredentialPinMode&&!value)return toast('Backup-Passwort eingeben');
    const resolve=backupCredentialResolver; backupCredentialResolver=null;
    $('backupCredentialDialog').close();
    input.value='';
    if(resolve)resolve(value);
  });
  $('backupCredentialDialog').addEventListener('close',()=>{
    $('backupCredentialForm').reset();
    if(backupCredentialResolver){const resolve=backupCredentialResolver;backupCredentialResolver=null;resolve(null);}
    backupCredentialPinMode=false;
  });
  $('enable2FABtn').addEventListener('click',openEnableTwoFactor);
  $('copyTwoFactorSecret').addEventListener('click',()=>copyText(pendingTwoFactorSecret||''));
  $('twoFactorSetupDialog').addEventListener('close',()=>{ if(!$('recoveryCodesDialog').open) clearTwoFactorSetup(); });
  $('twoFactorSetupForm').addEventListener('submit',async e=>{
    if(e.submitter?.value==='cancel'){clearTwoFactorSetup();return;} e.preventDefault();
    const pin=normalizePin($('twoFactorSetupPassword').value),code=$('twoFactorSetupCode').value;
    if(!isValidPin(pin))return toast('Master-PIN muss genau 6 Ziffern haben');
    try{const codes=await enableTwoFactor(pin,code);$('twoFactorSetupDialog').close();showRecoveryCodes(codes);}catch(err){toast(err?.message||'2FA konnte nicht aktiviert werden');}
  });
  $('copyRecoveryCodes').addEventListener('click',()=>copyText($('recoveryCodesText').value));
  $('closeRecoveryCodes').addEventListener('click',()=>{$('recoveryCodesDialog').close();});
  $('recoveryCodesDialog').addEventListener('close',()=>{$('recoveryCodesText').value='';});
  $('disable2FABtn').addEventListener('click',()=>{$('twoFactorManageAction').value='disable';$('twoFactorManageTitle').textContent='2FA deaktivieren';$('twoFactorManageForm').reset();$('twoFactorManageAction').value='disable';$('twoFactorManageDialog').showModal();});
  $('regenerateRecoveryBtn').addEventListener('click',()=>{$('twoFactorManageTitle').textContent='Recovery-Codes erneuern';$('twoFactorManageForm').reset();$('twoFactorManageAction').value='regenerate';$('twoFactorManageDialog').showModal();});
  $('twoFactorManageForm').addEventListener('submit',async e=>{
    if(e.submitter?.value==='cancel')return; e.preventDefault();
    const action=$('twoFactorManageAction').value,pin=normalizePin($('twoFactorManagePassword').value),factor=$('twoFactorManageCode').value;
    if(!isValidPin(pin))return toast('Master-PIN muss genau 6 Ziffern haben');
    try{ if(action==='disable') await disableTwoFactor(pin,factor); else await regenerateRecoveryCodes(pin,factor); $('twoFactorManageDialog').close(); $('twoFactorManageForm').reset(); }catch(err){toast(err?.message||'2FA-Prüfung fehlgeschlagen');}
  });
  $('autoLockSelect').addEventListener('change',async()=>{sessionVault.settings.autoLockMinutes=Number($('autoLockSelect').value);await saveVault();resetAutoLock();toast('Auto-Sperre aktualisiert');});
  $('changePasswordBtn').addEventListener('click',()=>{$('changePasswordForm').reset();$('changePasswordDialog').showModal();});
  $('changePasswordForm').addEventListener('submit',async e=>{
    if(e.submitter?.value==='cancel')return; e.preventDefault();
    const a=normalizePin($('newPassword').value),b=normalizePin($('newPassword2').value),current=normalizePin($('currentPassword').value);
    if(!isValidPin(current)||!isValidPin(a))return toast('PIN muss genau 6 Ziffern haben');
    if(a!==b)return toast('Neue PINs stimmen nicht überein');
    $('changePasswordForm').reset();
    try{await changeMasterPin(current,a);$('changePasswordDialog').close();}catch{toast('Aktuelle PIN ist falsch');}
  });
  ['pointerdown','keydown','touchstart'].forEach(ev=>window.addEventListener(ev,()=>{if(sessionVault)resetAutoLock();},{passive:true}));
  window.addEventListener('focus',recoverCanceledFilePicker);
  document.addEventListener('visibilitychange',()=>{
    if(document.visibilityState==='visible') recoverCanceledFilePicker();
    if(document.visibilityState==='visible'&&pendingSessionVault&&pendingTwoFactorExpiresAt&&Date.now()>pendingTwoFactorExpiresAt){ expirePendingSecondFactor(); return; }
    if(document.visibilityState==='hidden'&&sessionVault&&!systemPickerActive&&!twoFactorSetupActive){
      setTimeout(()=>{if(document.visibilityState==='hidden'&&sessionVault&&!systemPickerActive&&!twoFactorSetupActive)lockVault();},5000);
    }
  });
  window.addEventListener('pagehide',()=>{ if(sessionVault&&!systemPickerActive) lockVault(); });
}

async function init(){
  if(window.top!==window.self){ document.documentElement.textContent='SafeBase darf nicht in einem eingebetteten Frame ausgeführt werden.'; return; }
  if(!window.isSecureContext){ alert('SafeBase benötigt eine sichere HTTPS-Verbindung.'); return; }
  if(!('indexedDB'in window)||!crypto?.subtle){alert('Dieser Browser unterstützt die benötigte lokale Verschlüsselung nicht.');return;}
  db=await openDB(); loadPinFailureState(); setupEvents(); generatePassword(); await requestPersistentStorage();
  const meta=await idbGet('meta',META_KEY);
  if(meta){
    if(isPinMeta(meta)){ unlockView.classList.remove('hidden'); statusText.textContent='Gesperrt • PIN'; }
    else { pinMigrationView.classList.remove('hidden'); statusText.textContent=`Einmalige PIN-Umstellung • v${DISPLAY_VERSION}`; }
  }else{ setupView.classList.remove('hidden'); statusText.textContent=`Ersteinrichtung • v${DISPLAY_VERSION}`; }
  await renderExternalDraftRecovery().catch(()=>{});
  if('serviceWorker'in navigator){navigator.serviceWorker.register('./service-worker.js').then(r=>r.update()).catch(()=>{});}
}
init().catch(()=>{alert('SafeBase konnte nicht gestartet werden.');});

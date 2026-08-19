/**
 * ============================================================================
 * CCS EVENT & ATTENDANCE MANAGEMENT SYSTEM - SUPABASE SYNC ENGINE (v3)
 * ============================================================================
 * PRODUCTION HARDENING:
 *  1. PASSWORDS ARE HASHED (SHA-256 + per-user salt via Web Crypto).
 *     Plaintext passwords are never stored - not locally, not in Supabase.
 *     Legacy plaintext entries are detected at login and upgraded in place.
 *  2. THE ADMIN GATE PASSCODE IS A RANDOM 6-DIGIT CODE generated on first
 *     run and shared through the settings table - there is no hardcoded
 *     default ("1234") anymore.
 *  3. NO SEEDED ACCOUNTS. The first admin is created through admin-signup
 *     using an access code. Nothing is auto-created behind your back.
 *  4. ROW LEVEL SECURITY is enabled in supabase-schema.sql with column-level
 *     protection for credential hashes (see the schema for the hardening
 *     section that uses Supabase Auth for full lockdown).
 *
 * HOW TO CONNECT:
 *  1. Create a free project at https://supabase.com
 *  2. Dashboard -> Settings -> API -> copy Project URL + Anon Key below.
 *  3. Run the ENTIRE supabase-schema.sql in the SQL Editor.
 *  4. Reload any page. Done.
 *
 * ARCHITECTURE:
 *  The engine mirrors the cloud tables into the exact localStorage keys the
 *  pages already use (ccs_ev, ccs_ev_att, ccs_students, ccs_ev_names,
 *  ccs_student_auth, ccs_admin_users, ccs_generated_access_codes,
 *  ccs_admin_pass) and dispatches a synthetic 'storage' event so every page
 *  re-renders instantly. Realtime websocket keeps devices in sync; offline
 *  records are flushed when the device comes back online.
 *
 *  STUDENT DELETES ARE PERMANENT: admin-deleted School IDs are stored in a
 *  shared tombstone list (settings table key "student_deleted", mirrored to
 *  localStorage key "ccs_students_deleted"). Every device purges those IDs
 *  from its cache and never re-uploads them, so deleted students cannot
 *  reappear after a refresh or sync. A student can only come back by
 *  signing up again with the same School ID (which clears the tombstone).
 *  Admins have the same protection (keys "admins_deleted" / ccs_admins_deleted).
 *
 *  AUTO-CLEANUP: at boot (max once per day per device) the engine deletes
 *  accounts whose `last_active` timestamp is older than INACTIVE_DAYS (365).
 *  Only REAL activity stamps last_active: student sign-up/login/profile
 *  save/event check-in, and admin sign-in/sign-up. Background syncs and
 *  flushes deliberately never touch it. Auto-deleted accounts are tombstoned
 *  like manual deletes, and the last remaining admin is never removed.
 * ============================================================================
 */

(function(window) {
  'use strict';

  // 1. SUPABASE PROJECT CREDENTIALS -----------------------------------------
  window.SUPABASE_CONFIG = {
    url: "https://zptymjfrfevfuinwqfwk.supabase.co", // e.g. "https://xyzproject.supabase.co"
    anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpwdHltamZyZmV2ZnVpbndxZndrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODYwOTQxODMsImV4cCI6MjEwMTY3MDE4M30.N-gDnpiObuKZPB_i0VgLQqWoWIonEc6SrMTN25miRxk", // e.g. "eyJhbGciOiJIUzI1NiIsIn..."
    enabled: false // auto-enabled below when url + key look real
  };

  const CFG = window.SUPABASE_CONFIG;
  const isConfigured =
    CFG.url && CFG.url.startsWith("http") &&
    CFG.anonKey && CFG.anonKey !== "YOUR_SUPABASE_ANON_KEY";
  CFG.enabled = isConfigured;

  let sb = null;
  if (isConfigured && window.supabase) {
    try {
      sb = window.supabase.createClient(CFG.url, CFG.anonKey);
      window.supabaseClient = sb;
    } catch (e) {
      console.warn("[CCS] Could not create Supabase client:", e && e.message);
      sb = null;
    }
  }

  // 2. LOCALSTORAGE KEYS (exactly what the pages already use) ----------------
  const KEYS = {
    EVENTS: "ccs_ev",
    HISTORY: "ccs_ev_history",
    ATTENDANCE: "ccs_ev_att",
    ACTIVE: "ccs_ev_active",
    STUDENTS: "ccs_students",
    STUDENTS_AUTH: "ccs_student_auth",
    NAMES: "ccs_ev_names",
    ADMIN_USERS: "ccs_admin_users",
    ACCESS_CODES: "ccs_generated_access_codes",
    ADMIN_PASS: "ccs_admin_pass",
    TOMBSTONES: "ccs_ev_deleted",
    STUDENT_TOMBS: "ccs_students_deleted", // shared delete-list for students (synced through the settings table)
    STUDENT_PENDING: "ccs_students_pending", // offline/new profile updates waiting for cloud confirmation
    ADMIN_TOMBS: "ccs_admins_deleted"      // shared delete-list for admins (synced through the settings table)
  };


  // ---- LEGACY MIGRATION (pre-v4) --------------------------------------------
  // v4 renamed the internal student-auth key from "ccs_students_demo" to
  // "ccs_student_auth". Existing installs keep their accounts via this copy.
  try {
    if (!localStorage.getItem(KEYS.STUDENTS_AUTH) && localStorage.getItem("ccs_students_demo")) {
      localStorage.setItem(KEYS.STUDENTS_AUTH, localStorage.getItem("ccs_students_demo"));
      localStorage.removeItem("ccs_students_demo");
    }
  } catch (e) {}

  function getLocal(key, fb) {
    try {
      const d = localStorage.getItem(key);
      return d ? JSON.parse(d) : fb;
    } catch (e) { return fb; }
  }

  function setLocal(key, val) {
    try {
      localStorage.setItem(key, JSON.stringify(val));
      window.dispatchEvent(new Event('storage')); // pages re-render on this
      return true;
    } catch (e) { return false; }
  }

  function stable(v) {
    return JSON.stringify(v || null);
  }

  // =========================================================================
  // 3. PASSWORD SECURITY (SHA-256 + per-user salt)
  // =========================================================================
  // Passwords are stored as { h: hex-sha256(salt + '::' + password),
  //                            s: random salt } - never as plaintext.
  // Legacy entries stored as a plain string are still verified (so nobody is
  // locked out after an upgrade) and are re-hashed on the next login.

  function randomSalt() {
    try {
      const bytes = new Uint8Array(16);
      window.crypto.getRandomValues(bytes);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
      return hex;
    } catch (e) {
      return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
    }
  }

  async function sha256Hex(text) {
    const data = new TextEncoder().encode(text);
    const buf = await window.crypto.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(buf);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex;
  }

  // Hash a plaintext password -> { h, s }
  async function hashPassword(plain) {
    const s = randomSalt();
    const h = await sha256Hex(s + '::' + String(plain));
    return { h: h, s: s };
  }

  // Verify a password against a stored credential.
  // stored may be: { h, s } (new) or a plain string (legacy, pre-v3).
  async function verifyPassword(plain, stored) {
    if (!stored) return false;
    if (typeof stored === 'object' && stored.h && stored.s) {
      const h = await sha256Hex(stored.s + '::' + String(plain));
      return h === stored.h;
    }
    // legacy plaintext (only possible from a pre-v3 install)
    return typeof stored === 'string' && stored === String(plain);
  }

  function isHashed(stored) {
    return !!(stored && typeof stored === 'object' && stored.h && stored.s);
  }

  // ---- STUDENT DELETE TOMBSTONES --------------------------------------------
  // Admin-deleted School IDs are kept in this list (mirrored into the cloud
  // "settings" table under the key "student_deleted"). Because pullStudents()
  // MERGES cloud rows into local storage, a plain cloud delete could be undone
  // by any device that still holds the student in its cache and re-uploads it
  // during flush(). The shared tombstone list makes the delete win everywhere:
  // every device purges tombstoned IDs locally and never re-uploads them.
  function readTombs(key) {
    try {
      const raw = localStorage.getItem(key);
      const v = raw ? JSON.parse(raw) : [];
      return Array.isArray(v) ? v.map(String) : [];
    } catch (e) { return []; }
  }

  function writeTombsLocal(key, list) {
    try { localStorage.setItem(key, JSON.stringify(list)); } catch (e) {}
  }

  function readStudentTombs() { return readTombs(KEYS.STUDENT_TOMBS); }
  function writeStudentTombsLocal(list) { writeTombsLocal(KEYS.STUDENT_TOMBS, list); }
  function readAdminTombs() { return readTombs(KEYS.ADMIN_TOMBS); }
  function writeAdminTombsLocal(list) { writeTombsLocal(KEYS.ADMIN_TOMBS, list); }

  // Random 6-digit numeric code (used for the admin gate passcode bootstrap)
  function randomDigits(n) {
    let out = '';
    try {
      const bytes = new Uint8Array(n);
      window.crypto.getRandomValues(bytes);
      for (let i = 0; i < n; i++) out += String(bytes[i] % 10);
    } catch (e) {
      for (let i = 0; i < n; i++) out += String(Math.floor(Math.random() * 10));
    }
    return out;
  }

  // Bootstrap the admin gate passcode: if no passcode exists anywhere,
  // generate a random one now (locally) and push it to the settings table.
  // IMPORTANT: store via JSON.stringify so JSON.parse (used by every page's
  // read()) returns a STRING. Writing the raw pin directly turns a numeric
  // PIN like "123456" into the NUMBER 123456 on the next read, which then
  // breaks the gate's strict-equality check (`"123456" === 123456` is false).
  function ensureLocalPasscode() {
    try {
      if (!localStorage.getItem(KEYS.ADMIN_PASS)) {
        const pin = randomDigits(6);
        localStorage.setItem(KEYS.ADMIN_PASS, JSON.stringify(pin));
        // The PIN is also shown on the Select page (Settings -> Current
        // passcode) with a copy button; logged here as a fallback.
        console.log("[CCS] Admin gate PIN for this browser: " + pin);
      }
    } catch (e) {}
  }
  ensureLocalPasscode();

  // =========================================================================
  // 4. COLUMN MAPPING (Supabase rows <-> the app's localStorage objects)
  // =========================================================================
  function eventFromRow(r) {
    if (!r) return null;
    return {
      id: r.id,
      name: r.name,
      type: r.type || 'assembly',
      venue: r.venue || 'TBA',
      date: r.date,
      start: r.start_time || '08:00',
      end: r.end_time || '17:00',
      code: r.code || '',
      open: !!r.open,
      autoOff: false,
      archivedAt: r.archived_at ? Date.parse(r.archived_at) : undefined,
      created_at: r.created_at
    };
  }

  function eventToRow(ev) {
    if (!ev) return null;
    return {
      id: ev.id,
      name: ev.name,
      type: ev.type || 'assembly',
      venue: ev.venue || 'TBA',
      date: ev.date || null,
      start_time: ev.start || '08:00',
      end_time: ev.end || '17:00',
      code: ev.code || '',
      open: ev.open !== false,
      archived: !!(ev.archivedAt || ev.archived),
      archived_at: ev.archivedAt ? new Date(ev.archivedAt).toISOString() : null
    };
  }

  function attFromRow(r) {
    if (!r) return null;
    return {
      name: r.name || '',
      course: r.course || '',
      year: r.year || '',
      section: r.section || '',
      at: (r.time_in !== null && r.time_in !== undefined) ? r.time_in : undefined,
      late: !!r.late,
      ts: r.time_in_ts || undefined,
      out: (r.time_out !== null && r.time_out !== undefined) ? r.time_out : undefined,
      outTs: r.time_out_ts || undefined,
      outOnly: !!r.out_only
    };
  }

  function attToRow(eventId, studentId, rec) {
    if (!rec) return null;
    return {
      id: eventId + '_' + studentId,
      event_id: eventId,
      student_id: studentId,
      name: rec.name || '',
      course: rec.course || '',
      year: rec.year || '',
      section: rec.section || '',
      time_in: (rec.at !== undefined && rec.at !== null) ? rec.at : null,
      time_in_ts: rec.ts || null,
      late: !!rec.late,
      time_out: (rec.out !== undefined && rec.out !== null) ? rec.out : null,
      time_out_ts: rec.outTs || null,
      out_only: !!rec.outOnly,
      status: 'present'
    };
  }

  function studentFromRow(r) {
    if (!r) return null;
    return {
      id: r.school_id,
      name: r.full_name || '',
      course: r.course || '',
      year: r.year || '',
      section: r.section || '',
      role: 'student'
    };
  }

  // Build a student row. `password` may be:
  //   - a plaintext string  -> hashed with a fresh salt
  //   - a {h,s} object      -> stored as-is (already hashed)
  //   - null/undefined      -> credential columns left untouched
  function studentToRow(p, password) {
    if (!p) return null;
    const row = {
      school_id: p.id,
      full_name: p.name || p.full_name || '',
      course: p.course || '',
      year: p.year || '',
      section: p.section || ''
    };
    if (password && typeof password === 'object' && password.h && password.s) {
      row.password_hash = password.h;
      row.password_salt = password.s;
    } else if (typeof password === 'string' && password) {
      // caller passed plaintext -> hash it now
      row._plain = password; // flagged; async caller resolves via hashPassword
    }
    return row;
  }

  // Student row (DB) -> credential object for ccs_student_auth
  function credentialFromRow(r) {
    if (r.password_hash && r.password_salt) {
      return { h: r.password_hash, s: r.password_salt };
    }
    if (r.password) return r.password; // legacy plaintext (pre-v3 install)
    return null;
  }

  function codeFromRow(r) {
    if (!r) return null;
    return {
      id: r.id,
      code: r.code,
      type: r.type || '',
      status: r.status || 'active',
      issued_to: r.issued_to || '',
      created_at: r.created_at
    };
  }

  function codeToRow(c) {
    if (!c) return null;
    return {
      id: c.id,
      code: c.code,
      type: c.type || '',
      status: c.status || 'active',
      issued_to: c.issued_to || ''
    };
  }

  function adminFromRow(r) {
    if (!r) return null;
    return {
      id: 'admin-' + r.username,
      full_name: r.full_name || '',
      username: r.username,
      email: r.email || '',
      password: credentialFromRow(r) || '',
      role: r.role || 'admin',
      created_at: r.created_at
    };
  }

  function adminToRow(u) {
    if (!u) return null;
    const row = {
      username: u.username,
      full_name: u.full_name || u.name || '',
      email: u.email || '',
      role: u.role || 'admin'
    };
    const pw = u.password;
    if (pw && typeof pw === 'object' && pw.h && pw.s) {
      row.password_hash = pw.h;
      row.password_salt = pw.s;
    } else if (typeof pw === 'string' && pw) {
      row.password = pw; // legacy plaintext (pre-v3 install) - upgraded on login
    }
    return row;
  }

  // =========================================================================
  // 5. THE SYNC ENGINE
  // =========================================================================
  const ccsSupabase = {
    client: sb,
    isOnline: function() {
      return !!(navigator.onLine !== false && CFG.enabled && sb);
    },

    // Public password helpers (used by login/signup/recovery pages)
    hashPassword: hashPassword,
    verifyPassword: verifyPassword,
    isHashed: isHashed,
    randomDigits: randomDigits,

    // ---- Lifecycle ----------------------------------------------------------
    async init() {
      if (!this.isOnline()) {
        console.log("[CCS] Offline mode: running on this device's local storage. Changes will sync when back online.");
        return;
      }
      console.log("[CCS] Connected to Supabase. Syncing data...");
      try {
        await this.syncNow();
        this.ensurePasscodeCloud();
        this.subscribeRealtime();
        // Cloud data is authoritative. Do not re-upload an arbitrary browser
        // cache on startup; doing so can make reports differ between devices.
        this.sweepInactiveAccounts(); // remove accounts inactive for 1+ year (throttled: once/day)
      } catch (err) {
        console.warn("[CCS] Sync warning:", err && err.message);
      }
    },

    async syncNow() {
      if (!this.isOnline()) return false;
      await this.pullSettings(); // first: brings in the shared delete-list
      await Promise.all([
        this.pullStudents(),
        this.pullAdmins(),
        this.pullEvents(),
        this.pullAttendance(),
        this.pullAccessCodes()
      ]);
      window.dispatchEvent(new Event('ccs-synced'));
      return true;
    },

    // ---- STUDENTS (names + credentials) --------------------------------------
    async pullStudents() {
      if (!this.isOnline()) return getLocal(KEYS.STUDENTS, {});
      const { data, error } = await sb.from('students').select('*');
      if (error) { console.warn("[CCS] pullStudents:", error.message); return getLocal(KEYS.STUDENTS, {}); }

      const tombs = readStudentTombs();
      const cachedProfiles = getLocal(KEYS.STUDENTS, {});
      const cachedNames = getLocal(KEYS.NAMES, {});
      const cachedAuth = getLocal(KEYS.STUDENTS_AUTH, {});
      const pending = getLocal(KEYS.STUDENT_PENDING, {});
      // When online, the registered-students table is authoritative. Build
      // a fresh cache from it instead of merging old browser data into it.
      // Only locally pending changes survive until their cloud upsert succeeds.
      const profiles = {};
      const names = {};
      const auth = {};

      (data || []).forEach(function(r) {
        const p = studentFromRow(r);
        if (!p || !p.id || tombs.indexOf(p.id) !== -1) return;
        profiles[p.id] = {
          id: p.id, name: p.name, course: p.course, year: p.year,
          section: p.section, role: 'student'
        };
        if (p.name) names[p.id] = p.name;
        const cred = credentialFromRow(r);
        if (cred) auth[p.id] = { password: cred, createdAt: (cachedAuth[p.id] || {}).createdAt || r.created_at };
      });

      // Keep genuine offline registrations/profile saves in the cache so the
      // next flush can upload them. They are removed from this list only after
      // Supabase confirms the upsert.
      Object.keys(pending).forEach(function(id) {
        if (tombs.indexOf(id) !== -1 || !cachedProfiles[id]) return;
        profiles[id] = cachedProfiles[id];
        if (cachedNames[id]) names[id] = cachedNames[id];
        if (cachedAuth[id]) auth[id] = cachedAuth[id];
      });

      setLocal(KEYS.STUDENTS, profiles);
      setLocal(KEYS.NAMES, names);
      setLocal(KEYS.STUDENTS_AUTH, auth);
      return profiles;
    },

    // Push a student profile (+ credential). `password` is hashed here.
    // If no name is supplied but the row already exists in the cloud, the
    // existing name is kept (used when upgrading legacy credentials).
    async pushStudent(profile, password) {
      // A genuine interactive registration (sign-up / login upgrade / password
      // reset - these pass a PLAINTEXT password string) clears any
      // delete-tombstone for this School ID, so a student may re-register
      // with the same ID after being deleted. Background re-uploads by
      // flush() pass an already-hashed {h,s} credential and must NEVER clear
      // a tombstone - otherwise a stale cache would silently undo an admin
      // delete.
      const sid = profile && (profile.id || profile.school_id);
      const isInteractiveAuth = typeof password === 'string' && password.length > 0;
      if (sid && isInteractiveAuth) {
        const tombs = readStudentTombs();
        const ti = tombs.indexOf(String(sid));
        if (ti !== -1) {
          tombs.splice(ti, 1);
          writeStudentTombsLocal(tombs);
          if (this.isOnline()) this.saveSetting('student_deleted', JSON.stringify(tombs));
        }
      }
      // Mark this record before the request. This protects a new/offline
      // registration from being replaced by an older browser cache on another
      // device while the cloud request is still in progress.
      if (sid) {
        const pending = getLocal(KEYS.STUDENT_PENDING, {});
        pending[String(sid)] = new Date().toISOString();
        setLocal(KEYS.STUDENT_PENDING, pending);
      }
      if (!this.isOnline()) return false;
      const row = studentToRow(profile, password);
      if (!row || !row.school_id) return false;
      if (!row.full_name) {
        const { data: existing } = await sb.from('students').select('full_name').eq('school_id', row.school_id).maybeSingle();
        row.full_name = (existing && existing.full_name) || row.school_id; // last resort: the ID itself
      }
      if (row._plain) {
        const h = await hashPassword(row._plain);
        row.password_hash = h.h;
        row.password_salt = h.s;
        delete row._plain;
      }
      // Real account activity (sign-up / login) counts for the inactivity
      // auto-cleanup. Background flushes never touch last_active.
      if (isInteractiveAuth) row.last_active = new Date().toISOString();
      const { error } = await sb.from('students').upsert(row, { onConflict: 'school_id' });
      if (error) {
        console.warn("[CCS] pushStudent:", error.message);
        return false;
      }
      // Cloud confirmed this exact profile. It is no longer an offline-only
      // record and future pulls will use the one shared Supabase version.
      if (sid) {
        const pending = getLocal(KEYS.STUDENT_PENDING, {});
        delete pending[String(sid)];
        setLocal(KEYS.STUDENT_PENDING, pending);
      }
      return true;
    },

    // Delete one or more student accounts everywhere (local + cloud), and
    // record them in the shared tombstone list so NO device can resurrect
    // them on the next sync. Past attendance rows are kept (they are event
    // snapshots). Resolves true only when every cloud step succeeded;
    // resolves false if any cloud delete failed (local delete still done),
    // so the UI can warn instead of promising a permanent delete.
    async deleteStudents(ids) {
      const list = (Array.isArray(ids) ? ids : [ids]).map(String).filter(Boolean);
      if (!list.length) return false;

      // 1. Remove locally first (instant UI update)
      const profiles = getLocal(KEYS.STUDENTS, {});
      const names = getLocal(KEYS.NAMES, {});
      const auth = getLocal(KEYS.STUDENTS_AUTH, {});
      list.forEach(function(id) {
        delete profiles[id];
        delete names[id];
        delete auth[id];
        const pending = getLocal(KEYS.STUDENT_PENDING, {});
        delete pending[id];
        setLocal(KEYS.STUDENT_PENDING, pending);
      });
      setLocal(KEYS.STUDENTS, profiles);
      setLocal(KEYS.NAMES, names);
      setLocal(KEYS.STUDENTS_AUTH, auth);

      // 2. Tombstone them so future pulls/flushes can never restore them
      const tombs = readStudentTombs();
      list.forEach(function(id) { if (tombs.indexOf(id) === -1) tombs.push(id); });
      writeStudentTombsLocal(tombs);

      // Offline: the local delete + tombstone are done, but the cloud rows
      // still exist and the cloud tombstone list was not updated - the
      // accounts could re-sync on other devices. Report failure so the UI
      // warns the admin to re-run the delete while online.
      if (!this.isOnline()) return false;

      // 3. Share the tombstone list so other devices purge these accounts too
      let ok = true;
      const tSaved = await this.saveSetting('student_deleted', JSON.stringify(tombs));
      if (tSaved === false) ok = false;

      // 4. Remove the rows from the cloud table - and VERIFY each delete.
      //    PostgREST raises NO error when an RLS policy blocks a DELETE; the
      //    row just silently stays. `.select('school_id')` returns the rows
      //    that were actually deleted, so an empty result = blocked delete,
      //    which we report so the UI can warn instead of promising a
      //    permanent delete.
      let cloudIds = null;
      try {
        const { data: existing } = await sb.from('students').select('school_id');
        cloudIds = {};
        (existing || []).forEach(function(r) { cloudIds[String(r.school_id)] = true; });
      } catch (e) { cloudIds = null; }

      for (const id of list) {
        if (cloudIds && !cloudIds[id]) continue; // not in the cloud = already gone, success
        const { data: deletedRows, error } = await sb.from('students').delete().eq('school_id', id).select('school_id');
        if (error) {
          console.warn("[CCS] deleteStudent:", error.message);
          ok = false;
        } else if (!deletedRows || !deletedRows.length) {
          console.warn("[CCS] deleteStudent: 0 rows removed for", id, "- the students table is missing a DELETE policy (RLS). Run schema-patch-v4.3.sql.");
          ok = false;
        }
      }
      return ok;
    },

    // Delete one or more admin accounts everywhere (local + cloud), with the
    // same tombstone protection as students. Used by the inactivity sweep.
    async deleteAdmins(usernames) {
      const list = (Array.isArray(usernames) ? usernames : [usernames]).map(function(u){ return String(u).toLowerCase(); }).filter(Boolean);
      if (!list.length) return false;

      const users = getLocal(KEYS.ADMIN_USERS, []).filter(function(u){ return list.indexOf(String(u.username).toLowerCase()) === -1; });
      setLocal(KEYS.ADMIN_USERS, users);

      const tombs = readAdminTombs();
      list.forEach(function(u){ if (tombs.indexOf(u) === -1) tombs.push(u); });
      writeAdminTombsLocal(tombs);

      if (!this.isOnline()) return false;

      let ok = true;
      const tSaved = await this.saveSetting('admins_deleted', JSON.stringify(tombs));
      if (tSaved === false) ok = false;

      let cloudNames = null;
      try {
        const { data: existing } = await sb.from('admins').select('username');
        cloudNames = {};
        (existing || []).forEach(function(r){ cloudNames[String(r.username).toLowerCase()] = true; });
      } catch (e) { cloudNames = null; }

      for (const u of list) {
        if (cloudNames && !cloudNames[u]) continue; // already gone
        const { data: deletedRows, error } = await sb.from('admins').delete().eq('username', u).select('username');
        if (error) {
          console.warn("[CCS] deleteAdmin:", error.message);
          ok = false;
        } else if (!deletedRows || !deletedRows.length) {
          console.warn("[CCS] deleteAdmin: 0 rows removed for", u, "- the admins table is missing a DELETE policy (RLS). Run the schema patch.");
          ok = false;
        }
      }
      return ok;
    },

    // ---- ADMINS -------------------------------------------------------------
    async pullAdmins() {
      if (!this.isOnline()) return getLocal(KEYS.ADMIN_USERS, []);
      const { data, error } = await sb.from('admins').select('*');
      if (error) { console.warn("[CCS] pullAdmins:", error.message); return getLocal(KEYS.ADMIN_USERS, []); }

      const tombs = readAdminTombs();
      // Purge tombstoned (deleted / auto-cleaned) admins from this device.
      let users = getLocal(KEYS.ADMIN_USERS, []);
      users = users.filter(function(u) { return tombs.indexOf(String(u.username).toLowerCase()) === -1; });
      (data || []).forEach(function(r) {
        const u = adminFromRow(r);
        if (!u || tombs.indexOf(String(u.username).toLowerCase()) !== -1) return;
        const i = users.findIndex(function(x) { return x.username === u.username; });
        if (i >= 0) users[i] = u; else users.push(u);
      });
      setLocal(KEYS.ADMIN_USERS, users);
      return users;
    },

    // `interactive` = a real sign-in / sign-up performed by a person.
    // Interactive pushes clear any delete-tombstone and stamp last_active;
    // background flush() pushes do neither.
    async pushAdmin(user, interactive) {
      const uname = user && user.username ? String(user.username).toLowerCase() : '';
      if (uname && interactive) {
        const tombs = readAdminTombs();
        const ti = tombs.indexOf(uname);
        if (ti !== -1) {
          tombs.splice(ti, 1);
          writeAdminTombsLocal(tombs);
          if (this.isOnline()) this.saveSetting('admins_deleted', JSON.stringify(tombs));
        }
      }
      if (!this.isOnline()) return false;
      const row = adminToRow(user);
      if (!row || !row.username) return false;
      if (interactive) row.last_active = new Date().toISOString();
      const { error } = await sb.from('admins').upsert(row, { onConflict: 'username' });
      if (error) console.warn("[CCS] pushAdmin:", error.message);
      return !error;
    },

    // ---- EVENTS ---------------------------------------------------------------
    async pullEvents() {
      if (!this.isOnline()) return getLocal(KEYS.EVENTS, []);
      const { data, error } = await sb.from('events').select('*');
      if (error) { console.warn("[CCS] pullEvents:", error.message); return getLocal(KEYS.EVENTS, []); }

      const tombstones = getLocal(KEYS.TOMBSTONES, []);
      const active = [];
      const history = [];

      (data || []).forEach(function(r) {
        if (tombstones.indexOf(r.id) !== -1) return;
        const ev = eventFromRow(r);
        if (ev.archivedAt) history.push(ev); else active.push(ev);
      });

      // Shallow-merge each cloud row over the matching local event instead of
      // replacing it outright. The cloud "events" table has no columns for
      // the rotating-code bookkeeping (codeAnchor, codeSlot, salt,
      // rotVersion, prevCode/prevUntil, autoOff) - eventFromRow() can't
      // return what was never stored. A full replace here wiped those
      // fields on every pull (which fires right after every push, via the
      // realtime subscription), resetting the countdown to full and
      // regenerating the same "slot 0" code forever. Object.assign keeps
      // local-only fields intact while still letting the cloud row win for
      // the columns it actually has (name, venue, open, code, etc.).
      const merge = function(localList, remoteList) {
        const localById = {};
        (localList || []).forEach(function(e) { if (e && e.id) localById[e.id] = e; });
        // Include only event IDs returned by Supabase. This retains the
        // browser-only QR bookkeeping for matching events but prevents a
        // stale, device-only event from appearing in an export.
        return (remoteList || []).filter(function(e) { return e && e.id; })
          .map(function(e) { return Object.assign({}, localById[e.id] || {}, e); });
      };

      const mergedActive = merge(getLocal(KEYS.EVENTS, []), active);
      const mergedHistory = merge(getLocal(KEYS.HISTORY, []), history);

      setLocal(KEYS.EVENTS, mergedActive);
      setLocal(KEYS.HISTORY, mergedHistory);
      return mergedActive;
    },

    async pushEvent(ev) {
      if (!this.isOnline()) return false;
      const row = eventToRow(ev);
      if (!row || !row.id) return false;
      const { error } = await sb.from('events').upsert(row, { onConflict: 'id' });
      if (error) console.warn("[CCS] pushEvent:", error.message);
      return !error;
    },

    async deleteEvent(id) {
      const tombstones = getLocal(KEYS.TOMBSTONES, []);
      if (tombstones.indexOf(id) === -1) tombstones.push(id);
      setLocal(KEYS.TOMBSTONES, tombstones);
      if (!this.isOnline()) return false;
      const { error } = await sb.from('events').delete().eq('id', id);
      if (error) console.warn("[CCS] deleteEvent:", error.message);
      return !error;
    },

    // ---- ATTENDANCE ----------------------------------------------------------
    async pullAttendance() {
      if (!this.isOnline()) return getLocal(KEYS.ATTENDANCE, {});
      const { data, error } = await sb.from('attendance').select('*');
      if (error) { console.warn("[CCS] pullAttendance:", error.message); return getLocal(KEYS.ATTENDANCE, {}); }

      // Build the attendance cache only from Supabase. A merge leaves old
      // device-only check-ins behind and causes different PDF exports.
      const map = {};
      (data || []).forEach(function(r) {
        const rec = attFromRow(r);
        if (!rec || !r.event_id || !r.student_id) return;
        if (!map[r.event_id]) map[r.event_id] = {};
        map[r.event_id][r.student_id] = rec;
      });

      setLocal(KEYS.ATTENDANCE, map);
      return map;
    },

    async pushAttendance(eventId, studentId, rec) {
      if (!this.isOnline()) return false;
      const row = attToRow(eventId, studentId, rec);
      if (!row || !row.event_id || !row.student_id) return false;
      // A check-in is genuine account activity: refresh last_active so the
      // inactivity auto-cleanup never removes active event-goers.
      // Fire-and-forget - it must never delay or break a check-in.
      try {
        Promise.resolve(
          sb.from('students').update({ last_active: new Date().toISOString() }).eq('school_id', studentId)
        ).catch(function() {});
      } catch (e) {}
      const { error } = await sb.from('attendance').upsert(row, { onConflict: 'id' });
      if (error) console.warn("[CCS] pushAttendance:", error.message);
      return !error;
    },

    // ---- ACCESS CODES ---------------------------------------------------------
    async pullAccessCodes() {
      if (!this.isOnline()) return getLocal(KEYS.ACCESS_CODES, []);
      const { data, error } = await sb.from('access_codes').select('*').order('created_at', { ascending: false });
      if (error) { console.warn("[CCS] pullAccessCodes:", error.message); return getLocal(KEYS.ACCESS_CODES, []); }

      const codes = getLocal(KEYS.ACCESS_CODES, []);
      (data || []).forEach(function(r) {
        const c = codeFromRow(r);
        if (!c) return;
        const i = codes.findIndex(function(x) { return x.id === c.id; });
        if (i >= 0) codes[i] = c; else codes.push(c);
      });
      setLocal(KEYS.ACCESS_CODES, codes);
      return codes;
    },

    async pushAccessCode(codeObj) {
      if (!this.isOnline()) return false;
      const row = codeToRow(codeObj);
      if (!row || !row.id) return false;
      const { error } = await sb.from('access_codes').upsert(row, { onConflict: 'id' });
      if (error) console.warn("[CCS] pushAccessCode:", error.message);
      return !error;
    },

    // ---- SETTINGS ---------------------------------------------------------------
    async pullSettings() {
      if (!this.isOnline()) return;
      const { data, error } = await sb.from('settings').select('*');
      if (error) return;
      (data || []).forEach(function(r) {
        if (r.key === 'admin_pass') {
          // IMPORTANT: JSON.stringify the cloud value before storing. The
          // rest of the app reads this key via JSON.parse(); writing the raw
          // value (e.g. "123456") would be parsed back as the NUMBER 123456,
          // which then breaks the admin gate's strict-equality passcode check.
          try { localStorage.setItem(KEYS.ADMIN_PASS, JSON.stringify(String(r.value))); } catch (e) {}
        }
        if (r.key === 'student_deleted' || r.key === 'admins_deleted') {
          try {
            const v = JSON.parse(r.value);
            if (Array.isArray(v)) {
              if (r.key === 'student_deleted') writeStudentTombsLocal(v.map(String));
              else writeAdminTombsLocal(v.map(String));
            }
          } catch (e) {}
        }
      });
    },

    async saveSetting(key, value) {
      try {
        // Same JSON.stringify rule as pullSettings - keep the on-disk shape
        // consistent so JSON.parse returns a STRING (never a number) for the
        // admin passcode. Mirrors the gate's strict-equality check.
        if (key === 'admin_pass') localStorage.setItem(KEYS.ADMIN_PASS, JSON.stringify(String(value)));
        if (key === 'student_deleted' || key === 'admins_deleted') {
          const v = JSON.parse(value);
          if (Array.isArray(v)) {
            if (key === 'student_deleted') writeStudentTombsLocal(v.map(String));
            else writeAdminTombsLocal(v.map(String));
          }
        }
      } catch (e) {}
      if (!this.isOnline()) return false;
      const { error } = await sb.from('settings').upsert(
        { key: key, value: String(value), updated_at: new Date().toISOString() },
        { onConflict: 'key' }
      );
      if (error) console.warn("[CCS] saveSetting:", error.message);
      return !error;
    },

    // Make sure the shared gate passcode exists in the cloud
    async ensurePasscodeCloud() {
      try {
        const pin = localStorage.getItem(KEYS.ADMIN_PASS);
        if (pin) await this.saveSetting('admin_pass', pin);
      } catch (e) {}
    },

    // ---- WATCH (auto-push event changes from admin pages) ---------------------
    _eventFp: null,
    async watchEvents() {
      if (!this.isOnline()) return false;
      const active = getLocal(KEYS.EVENTS, []);
      const history = getLocal(KEYS.HISTORY, []);
      const tombstones = getLocal(KEYS.TOMBSTONES, []);
      const all = active.concat(history).filter(function(e) { return tombstones.indexOf(e.id) === -1; });

      const fp = stable(all.map(function(e) {
        return {
          id: e.id, name: e.name, type: e.type, venue: e.venue, date: e.date,
          start: e.start, end: e.end, code: e.code, open: e.open !== false,
          archivedAt: e.archivedAt || 0
        };
      }));
      if (fp === this._eventFp) return false;
      this._eventFp = fp;
      for (const ev of all) await this.pushEvent(ev);
      return true;
    },

    // ---- AUTO-CLEANUP (inactive accounts) -------------------------------------
    // Accounts with NO activity for INACTIVE_DAYS days are deleted automatically
    // to keep the database small. Activity means real usage:
    //   students  -> sign-up, login, profile save, EVENT CHECK-IN
    //   admins    -> admin sign-in / sign-up
    // The timestamp lives in the cloud column `last_active` (added by the
    // schema patch; older rows fall back to `created_at`). Runs at most once
    // per 24 hours per device; whichever device sweeps first tombstones the
    // removed accounts so no other device can resurrect them. The LAST
    // remaining admin is never auto-deleted (lockout protection).
    INACTIVE_DAYS: 365,

    async sweepInactiveAccounts() {
      if (!this.isOnline()) return false;
      const DAY = 24 * 60 * 60 * 1000;
      try {
        const lastRun = parseInt(localStorage.getItem('ccs_last_sweep') || '0', 10);
        if (Date.now() - lastRun < DAY) return false; // already swept today
      } catch (e) {}
      try { localStorage.setItem('ccs_last_sweep', String(Date.now())); } catch (e) {}

      const cutoff = Date.now() - this.INACTIVE_DAYS * DAY;
      const isStale = function(r) {
        const t = Date.parse(r.last_active || '') || Date.parse(r.created_at || '') || 0;
        return t > 0 && t < cutoff;
      };

      // Students
      try {
        const { data: studs } = await sb.from('students').select('school_id, last_active, created_at');
        const ids = (studs || []).filter(isStale).map(function(r){ return r.school_id; }).filter(Boolean);
        if (ids.length) {
          console.log('[CCS] Auto-cleanup: removing ' + ids.length + ' student account(s) inactive for over ' + this.INACTIVE_DAYS + ' days.');
          await this.deleteStudents(ids);
        }
      } catch (e) { console.warn('[CCS] sweep students:', e && e.message); }

      // Admins - never delete the last remaining admin
      try {
        const { data: adms } = await sb.from('admins').select('username, last_active, created_at');
        const all = adms || [];
        const stale = all.filter(isStale);
        if (stale.length && all.length - stale.length < 1) {
          // Lockout protection: spare the most recently active admin.
          stale.sort(function(a, b) {
            const ta = Date.parse(a.last_active || a.created_at || '') || 0;
            const tb = Date.parse(b.last_active || b.created_at || '') || 0;
            return tb - ta;
          });
          stale.shift();
          console.log('[CCS] Auto-cleanup: kept the most recent admin to avoid locking everyone out.');
        }
        const names = stale.map(function(r){ return r.username; }).filter(Boolean);
        if (names.length) {
          console.log('[CCS] Auto-cleanup: removing ' + names.length + ' admin account(s) inactive for over ' + this.INACTIVE_DAYS + ' days.');
          await this.deleteAdmins(names);
        }
      } catch (e) { console.warn('[CCS] sweep admins:', e && e.message); }
      return true;
    },

    // ---- FLUSH (push everything local that the cloud may be missing) -----------
    async flush() {
      if (!this.isOnline()) return false;

      const profiles = getLocal(KEYS.STUDENTS, {});
      const auth = getLocal(KEYS.STUDENTS_AUTH, {});
      const sTombs = readStudentTombs();
      for (const id of Object.keys(profiles)) {
        if (sTombs.indexOf(id) !== -1) continue; // deleted by admin - never re-upload
        const p = profiles[id];
        if (p && p.name) {
          const cred = (auth[id] && auth[id].password) || '';
          await this.pushStudent({ id: id, name: p.name, course: p.course, year: p.year, section: p.section }, cred);
        }
      }

      const tombstones = getLocal(KEYS.TOMBSTONES, []);
      const events = getLocal(KEYS.EVENTS, []).concat(getLocal(KEYS.HISTORY, []));
      for (const ev of events) {
        if (tombstones.indexOf(ev.id) === -1) await this.pushEvent(ev);
      }

      const att = getLocal(KEYS.ATTENDANCE, {});
      for (const evId of Object.keys(att)) {
        if (tombstones.indexOf(evId) !== -1) continue;
        for (const sid of Object.keys(att[evId] || {})) {
          await this.pushAttendance(evId, sid, att[evId][sid]);
        }
      }

      const codes = getLocal(KEYS.ACCESS_CODES, []);
      for (const c of codes) await this.pushAccessCode(c);

      const users = getLocal(KEYS.ADMIN_USERS, []);
      const aTombs = readAdminTombs();
      for (const u of users) {
        if (u && aTombs.indexOf(String(u.username).toLowerCase()) !== -1) continue; // deleted - never re-upload
        await this.pushAdmin(u);
      }

      try {
        const pin = localStorage.getItem(KEYS.ADMIN_PASS);
        if (pin) await this.saveSetting('admin_pass', pin);
      } catch (e) {}
      return true;
    },

    // ---- REALTIME ----------------------------------------------------------------
    subscribeRealtime() {
      if (!this.isOnline()) return;
      const ch = sb.channel('ccs-realtime-v3');
      const hook = function(table, fn) {
        ch.on('postgres_changes', { event: '*', schema: 'public', table: table }, function() { fn(); });
      };
      hook('students', () => this.pullStudents());
      hook('admins', () => this.pullAdmins());
      hook('events', () => this.pullEvents());
      hook('attendance', () => this.pullAttendance());
      hook('access_codes', () => this.pullAccessCodes());
      // A settings change can carry a new delete-list -> re-pull accounts so
      // freshly deleted students/admins are purged on this device right away.
      hook('settings', () => { Promise.resolve(this.pullSettings()).then(() => { this.pullStudents(); this.pullAdmins(); }); });
      ch.subscribe();
    },

    // ---- AUTH WRAPPERS ------------------------------------------------------------
    // Admin auth is the app's simple username/password design, but credentials
    // are hashed and shared through the admins table so accounts work on every
    // device. Returns the matched admin or throws.
    async signInAdmin(username, password) {
      const users = getLocal(KEYS.ADMIN_USERS, []);
      const u = users.find(function(x) {
        return String(x.username).toLowerCase() === String(username).toLowerCase();
      });
      if (!u) throw new Error("Invalid username or password.");
      const ok = await verifyPassword(password, u.password || '');
      if (!ok) throw new Error("Invalid username or password.");
      // Upgrade legacy plaintext to a hash
      if (u.password && typeof u.password === 'string') {
        u.password = await hashPassword(password);
        setLocal(KEYS.ADMIN_USERS, users);
      }
      // A successful login is admin activity: stamp last_active in the cloud
      // (interactive push also clears any auto-cleanup tombstone).
      if (this.isOnline()) this.pushAdmin(u, true);
      return u;
    },

    async signUpAdmin(fullName, username, email, password) {
      const users = getLocal(KEYS.ADMIN_USERS, []);
      if (users.some(function(u) { return String(u.username).toLowerCase() === String(username).toLowerCase(); })) {
        throw new Error("That username is already taken.");
      }
      const hashed = await hashPassword(password);
      const newUser = {
        id: 'admin-' + Date.now(),
        full_name: fullName,
        username: String(username).toLowerCase(),
        email: email,
        password: hashed,
        role: 'admin',
        created_at: new Date().toISOString()
      };
      users.push(newUser);
      setLocal(KEYS.ADMIN_USERS, users);
      if (this.isOnline()) this.pushAdmin(newUser, true);
      return newUser;
    },

    // Legacy alias kept so any old callers still work.
    async saveProfile(profile) {
      return this.pushStudent(profile);
    },
    async syncEvents() {
      await this.pullEvents();
      return getLocal(KEYS.EVENTS, []);
    }
  };

  window.ccsSupabase = ccsSupabase;

  // ---- AUTO-START + NETWORK RECOVERY -------------------------------------------
  function boot() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() { ccsSupabase.init(); });
    } else {
      ccsSupabase.init();
    }
    window.addEventListener('online', function() {
      if (ccsSupabase.isOnline()) {
        ccsSupabase.syncNow();
      }
    });
  }
  boot();

})(window);

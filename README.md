# CCS Event & Attendance Management System — Supabase Edition

Fixed & cloud-synced version of the CCS app. Every page now works together
through **Supabase**, and student **names** finally show up correctly on every
device (the main fix).

---

## 1. What was broken and what I fixed

| Problem | Fix |
|---|---|
| **Forgot password was fake** — the old `forgot-password.html` just simulated a token and never changed anything | **New real recovery flow (v3.3):** enter your School ID (student) or admin username → the app verifies the account locally + in Supabase → generates a real 6-digit recovery code (10-min expiry, shown on screen because there's no email service) → set a new password → saved locally **and** pushed to Supabase so it works on every device. Wired from `login.html` (student) and `admin-login.html` (admin) |
| **Student names missing** on admin pages (Live / Absent / List / reports) — a student signed up on their phone, but the event laptop showed the raw ID or "Unregistered" | New `students` table keyed by school ID. Signup (`login.html`) and profile edits (`student-profile.html`) now push the name to Supabase; every admin/event page pulls it into `ccs_students` + `ccs_ev_names` automatically |
| **Attendance records lost their name/course/year** when synced (the old engine stored only time-in + status) | New `attendance` table stores the FULL record (`name, course, year, section, time_in, time_in_ts, late, time_out, time_out_ts, out_only`); check-ins in `student-checkin.html` push the full record both on time-in and time-out |
| **Nothing actually synced** — `supabase-config.js` was loaded by every page but no page ever called it, so events/attendance/signups stayed stuck on one device | Every write path is now wired: signup, login, profile save, check-in/out, event create/edit/end/delete, passcode change, admin signup/login, access-code generation |
| **Admin login had a dead "Forgot password?" link** (it just showed an error message) | Now navigates to `forgot-password.html?mode=admin` with the real recovery flow |
| **Landing pages (`index.html`, `ccs.html`) didn't load the sync engine** | Engine scripts added for consistency |
| **Student login only worked on the device where they registered** | `ccs_students_demo` (the login database) is rebuilt from the `students` table on every pull, so students can sign in on any device |
| **Admin accounts only worked on one device** | `admins` table synced with `ccs_admin_users`; `admin-login.html` pulls the cloud list before checking, `admin-signup.html` pushes new accounts (and validates access codes pulled from the cloud) |
| **Access codes generated on one device were invisible on others** | `access_codes` table synced with `ccs_generated_access_codes` (note: the old engine used `code_string`, the generator page uses `code` — that mismatch is fixed) |
| Old engine used fake Supabase email auth (`user@ccsadmin.local`) that could never sign in | Admin auth stays on the app's simple local design but is now shared through the `admins` table |
| Offline records never reached the cloud | `flush()` re-uploads everything made offline when the device comes back online |

## 2. Setup (5 minutes)

1. **Create a Supabase project** (free) at https://supabase.com
2. **Open `supabase-schema.sql`** and run the ENTIRE file in your project's
   **SQL Editor**. This creates:
   - `students` (school ID = primary key → names work everywhere)
   - `admins` (username = primary key)
   - `events` (active + archived, check-in code, open flag)
   - `attendance` (full check-in records with names)
   - `access_codes` (generated admin codes)
   - `settings` (key/value, e.g. the admin gate PIN)
   - realtime publication for all tables + `updated_at` triggers
3. **Copy your Project URL and Anon Key** into the top of
   `supabase-config.js`:
   ```js
   window.SUPABASE_CONFIG = {
     url: "https://YOURPROJECT.supabase.co",
     anonKey: "YOUR_ANON_KEY",
     ...
   };
   ```
   (The values already in the file are from the old project — replace them if
   you create a new one, or keep them if the project still exists.)
4. Upload the whole folder (all `.html` + `supabase-config.js`) to your web
   host, or open the files locally — everything works either way.

> **No Supabase? No problem.** The app still runs 100% offline on
> localStorage. The engine detects it and skips cloud calls. When the device
> is online again, offline records are flushed up.

## 3. How the sync works (for all pages)

```
Student phone:            signup / profile save  ──►  students table
Student phone:            check-in / time-out    ──►  attendance table
Admin laptop:             event create / edit / end / delete ──► events table
Admin laptop:             toggle open, rotating code ──► events table (watchEvents)
Admin laptop:             access code generated  ──►  access_codes table
Admin laptop:             admin signup / login   ──►  admins table
Admin laptop:             gate PIN changed       ──►  settings table
ANY device:               page load ──► pulls everything into localStorage
                          realtime websocket ──► instant re-pull on changes
```

The engine writes into the **exact same localStorage keys** the pages already
use (`ccs_ev`, `ccs_ev_att`, `ccs_students`, `ccs_ev_names`, ...) and fires a
synthetic `storage` event so every page re-renders instantly — no page
rewrites were needed, just small sync hooks at each write point.

## 4. Files

| File | What it is |
|---|---|
| `supabase-config.js` | **Sync engine (v4 - production)** — hashed passwords (SHA-256 + salt), random gate passcode, realtime, offline flush, legacy migration |
| `supabase-schema.sql` | **Production schema (v4)** — RLS enabled, hashed credential columns; run once in the Supabase SQL Editor |
| `*.html` (18 pages) | All pages, wired with sync hooks + secure auth |

## 5. Production hardening (v4)

- **Passwords are NEVER stored in plaintext.** Every credential is stored as
  a salted SHA-256 hash (`{ h, s }`), locally and in Supabase
  (`password_hash` + `password_salt` columns). Legacy plaintext entries from
  older versions are detected at login and upgraded to hashes in place.
- **No default/seed admin.** The old `ccsadmin / admin123` account is gone.
  The first admin is created through `admin-signup.html` with an access code.
- **No hardcoded gate passcode.** The admin gate PIN is a random 6-digit code
  generated on first run, stored in `ccs_admin_pass` and shared through the
  `settings` table. Change it anytime on the Select page.
- **Row Level Security is ENABLED** in the schema with minimal policies for a
  school-network deployment, plus a commented section 11 for full Supabase
  Auth lockdown on public deployments.
- **Forgot-password** is a real flow: School ID/username → 6-digit code
  (10-min expiry) → new password (hashed). If no email service is configured
  the code is displayed on screen; wire it to Supabase email auth for emailed
  codes.
- **Deleted events** use a lightweight tombstone list (`ccs_ev_deleted`) so
  they don't resurrect on other devices.
- The app still works 100% offline on one device; the engine flushes offline
  records to the cloud when connectivity returns.
- `supabase-schema.sql` disables Row Level Security for the demo so the anon
  key works out of the box; production policies are included as comments.

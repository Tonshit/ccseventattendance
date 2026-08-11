-- ============================================================================
-- CCS EVENT & ATTENDANCE MANAGEMENT SYSTEM - SCHEMA PATCH (v4.3)
-- ============================================================================
-- WHAT THIS FIXES / ADDS:
--
--   1. MISSING DELETE POLICIES (critical):
--      The students and admins tables have RLS enabled but only SELECT /
--      INSERT / UPDATE policies. Without a DELETE policy, Supabase SILENTLY
--      ignores account deletions ("Delete Selected" / "Delete All" in
--      event-list.html, and the new inactivity auto-cleanup) - the rows
--      stay and the accounts reappear after refresh.
--
--   2. NEW COLUMN `last_active` on students + admins:
--      Powers the 1-year inactivity auto-cleanup. Only REAL activity stamps
--      it (login / sign-up / profile save / event check-in). The existing
--      `updated_at` column CANNOT be used for this: its trigger bumps it on
--      every sync/flush upsert, so every account would look "active" forever.
--      Existing accounts are backfilled from updated_at/created_at so nobody
--      is deleted by surprise - their 1-year clock starts from today.
--
--   Safe to run multiple times (idempotent). Run AFTER your v4.1 schema.
--
-- HOW TO USE:
--   1. Supabase Dashboard -> SQL Editor
--   2. Paste this ENTIRE file and click RUN
--   3. Deploy the updated supabase-config.js + event-list.html
--   4. Test: event-list.html -> Delete All -> refresh -> list stays empty
-- ============================================================================

-- 1. DELETE policies ---------------------------------------------------------
DROP POLICY IF EXISTS students_delete ON students;
CREATE POLICY students_delete ON students
  FOR DELETE USING (true);

DROP POLICY IF EXISTS admins_delete ON admins;
CREATE POLICY admins_delete ON admins
  FOR DELETE USING (true);

-- 2. Activity tracking columns ------------------------------------------------
ALTER TABLE students ADD COLUMN IF NOT EXISTS last_active TIMESTAMPTZ;
ALTER TABLE admins   ADD COLUMN IF NOT EXISTS last_active TIMESTAMPTZ;

-- 3. Backfill existing accounts so the 1-year clock starts fairly -------------
UPDATE students SET last_active = COALESCE(last_active, updated_at, created_at, NOW());
UPDATE admins   SET last_active = COALESCE(last_active, updated_at, created_at, NOW());

-- ============================================================================
-- VERIFY (optional): this should list both new policies and both new columns:
--
--   SELECT tablename, policyname FROM pg_policies
--   WHERE schemaname = 'public' AND policyname LIKE '%_delete';
--
--   SELECT table_name, column_name FROM information_schema.columns
--   WHERE table_schema = 'public' AND column_name = 'last_active';
-- ============================================================================
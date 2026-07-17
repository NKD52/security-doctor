-- Add historical sync flag to JF_Onboarding_Form
ALTER TABLE "JF_Onboarding_Form" 
ADD COLUMN IF NOT EXISTS is_historical_sync BOOLEAN DEFAULT FALSE;
-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_jf_onboarding_historical ON "JF_Onboarding_Form"(is_historical_sync);
-- Create sync audit table for rollback capability
CREATE TABLE IF NOT EXISTS sync_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sync_batch_id UUID NOT NULL,
  submission_id TEXT NOT NULL,
  sync_type TEXT NOT NULL,
  old_values JSONB,
  new_values JSONB,
  synced_at TIMESTAMPTZ DEFAULT NOW(),
  synced_by TEXT
);
-- Create indexes for sync_audit
CREATE INDEX IF NOT EXISTS idx_sync_audit_batch ON sync_audit(sync_batch_id);
CREATE INDEX IF NOT EXISTS idx_sync_audit_submission ON sync_audit(submission_id);
CREATE INDEX IF NOT EXISTS idx_sync_audit_synced_at ON sync_audit(synced_at DESC);

-- Applications may reference certificates; refuse delete when still linked.
UPDATE applications
  SET certificate_id = NULL
  WHERE certificate_id IS NOT NULL
    AND certificate_id NOT IN (SELECT id FROM certificates);

ALTER TABLE applications
  DROP CONSTRAINT IF EXISTS applications_certificate_id_fkey;

ALTER TABLE applications
  ADD CONSTRAINT applications_certificate_id_fkey
  FOREIGN KEY (certificate_id) REFERENCES certificates(id)
  ON DELETE RESTRICT;

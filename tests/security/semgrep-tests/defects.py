# ruleid: shell-text-command
subprocess.run(command, shell=True, check=True)

# ok: shell-text-command
subprocess.run(["bash", "-c", command], check=True)

# ruleid: shell-text-command-argv
subprocess.run(["bash", "-ceu", 'psql -tAqc "' + query + '"'], check=True)

# ruleid: shell-text-command-argv
subprocess.run(["sh", "-c", f"psql -c {query}"], check=True)

# ok: shell-text-command-argv
subprocess.run(["bash", "-ceu", 'psql -tAqc "$1"', "bash", query], check=True)

# ruleid: shell-text-command-argv
run([*command, "exec", "-T", "postgres", "/bin/bash", "-ceu", "pg_dump " + options], check=True)

# ok: shell-text-command-argv
subprocess.run(["git", "-c", f"user.name={name}", "status"], check=True)



# ruleid: sql-interpolation-python
cursor.executemany(f"INSERT INTO {table} (value) VALUES (%s)", rows)

# ok: sql-interpolation-python
cursor.executemany("INSERT INTO events (value) VALUES (%s)", rows)



# ruleid: unkeyed-identifier-hash-sql
sql = "CREATE FUNCTION token(subject uuid, p_random_device_id text) RETURNS text AS $$ SELECT encode(digest(subject::text || ':' || p_random_device_id, 'sha256'),'hex') $$ LANGUAGE sql;"
# ruleid: unkeyed-identifier-hash-sql
sql = "SELECT md5(NEW.study_id::text || ':' || identity.participant_id);"
# ruleid: unkeyed-identifier-hash-sql
sql = 'CREATE POLICY sample ON devices USING (fingerprint = sha256(source_random_device_id));'
# ruleid: unkeyed-identifier-hash-sql
sql = """SELECT digest(
    coalesce(label, '') || NEW.participant_id, 'sha256');"""

# ok: unkeyed-identifier-hash-sql
sql = 'SELECT chronicle_participant_block_token(study_id, participant_id);'
sql = "SELECT encode(hmac(participant_id, key_bytes, 'sha256'), 'hex');"
sql = "SELECT encode(hmac(body, key_bytes, 'sha256'), 'hex');"
sql = "ALTER TABLE usage ADD COLUMN labels_hash bytea GENERATED ALWAYS AS (digest(coalesce(app_name, '') || coalesce(web_domain, ''), 'sha256')) STORED; ALTER TABLE usage ADD CONSTRAINT k UNIQUE (study_id, participant_id, labels_hash);"




# ruleid: host-system-bash-argv
subprocess.Popen(["/bin/bash", str(probe)], env=env)

# ruleid: host-system-bash-argv
subprocess.run(['/bin/bash', '-c', 'mapfile -t rows', 'fixture'], check=True)

# ok: host-system-bash-argv
subprocess.Popen([bash, str(probe)], env=env)

# ok: host-system-bash-argv
run([*command, "exec", "-T", "postgres", "/bin/bash", "-ceu", 'pg_dump "$1"', "bash", options], check=True)

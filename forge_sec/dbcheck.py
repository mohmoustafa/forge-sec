"""Live database checks (optional): connects to Postgres and verifies RLS/roles.

Needs psycopg or psycopg2 installed. Read-only queries only.
Usage: forge-sec dbcheck --dsn "host=... dbname=... user=... password=..."
"""
from __future__ import annotations

from .models import Finding, Severity


def _connect(dsn: str):
    try:
        import psycopg
        return psycopg.connect(dsn)
    except ImportError:
        try:
            import psycopg2
            return psycopg2.connect(dsn)
        except ImportError:
            raise RuntimeError(
                "install psycopg (pip install 'psycopg[binary]') for dbcheck")


def check_postgres(dsn: str) -> list[Finding]:
    findings: list[Finding] = []

    def add(rule, title, sev, loc, msg, rem):
        findings.append(Finding(rule_id=rule, title=title, severity=sev,
                                confidence="high", file=loc, line=1,
                                message=msg, remediation=rem,
                                engine="dbcheck", tags=["database", "live"]))

    conn = _connect(dsn)
    cur = conn.cursor()

    # 1. tables without RLS enabled (excluding system schemas)
    cur.execute("""
        SELECT n.nspname, c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema')
          AND NOT c.relrowsecurity""")
    no_rls = cur.fetchall()
    if no_rls:
        add("DB-001", "Tables without Row-Level Security", Severity.MEDIUM,
            "db:postgres",
            f"{len(no_rls)} user tables have RLS disabled: "
            + ", ".join(f"{s}.{t}" for s, t in no_rls[:10]),
            "ALTER TABLE ... ENABLE ROW LEVEL SECURITY + CREATE POLICY, or confirm isolation is enforced elsewhere.")

    # 2. superuser / overly broad roles
    cur.execute("SELECT rolname FROM pg_roles WHERE rolsuper AND rolname NOT LIKE 'pg_%'")
    supers = [r[0] for r in cur.fetchall()]
    for r in supers:
        add("DB-002", "Superuser role in use", Severity.HIGH, f"db:role:{r}",
            f"Role '{r}' has SUPERUSER.", "Use least-privilege roles for app connections.")

    # 3. roles with no password expiry / login + CREATEDB+CREATEROLE
    cur.execute("""SELECT rolname FROM pg_roles
                   WHERE rolcanlogin AND (rolcreatedb OR rolcreaterole)
                     AND rolname NOT LIKE 'pg_%'""")
    for (r,) in cur.fetchall():
        add("DB-003", "Login role with CREATEDB/CREATEROLE", Severity.MEDIUM,
            f"db:role:{r}", f"Role '{r}' can login and create DBs/roles.",
            "Split admin duties from app roles.")

    # 4. ssl enforcement
    cur.execute("SHOW ssl")
    if cur.fetchone()[0] != "on":
        add("DB-004", "PostgreSQL SSL disabled", Severity.HIGH, "db:postgres",
            "Server has ssl=off - traffic is plaintext.",
            "Enable ssl + hostssl in pg_hba.conf.")

    # 5. default postgres superuser still allowed remote
    cur.execute("SELECT count(*) FROM pg_hba_file_rules()")
    try:
        cur.execute("""SELECT type, database, user_name, address FROM pg_hba_file_rules()
                       WHERE user_name='postgres' OR address='0.0.0.0/0'""")
        wide = cur.fetchall()
        if wide:
            add("DB-005", "pg_hba allows postgres/0.0.0.0 access", Severity.HIGH,
                "db:postgres",
                f"{len(wide)} pg_hba rules expose the superuser or all addresses.",
                "Restrict pg_hba to needed subnets and non-superuser accounts.")
    except Exception:
        pass

    conn.close()
    return findings


def check_mysql(dsn: str) -> list[Finding]:
    """dsn: mysql://user:pass@host:3306/dbname (needs mysql-connector-python or pymysql)."""
    from urllib.parse import urlparse
    u = urlparse(dsn)
    findings: list[Finding] = []

    def add(rule, title, sev, loc, msg, rem):
        findings.append(Finding(rule_id=rule, title=title, severity=sev,
                                confidence="high", file=loc, line=1,
                                message=msg, remediation=rem,
                                engine="dbcheck", tags=["database", "live"]))
    try:
        import mysql.connector
        conn = mysql.connector.connect(host=u.hostname, port=u.port or 3306,
                                       user=u.username, password=u.password,
                                       database=u.path.lstrip("/"))
    except ImportError:
        try:
            import pymysql
            conn = pymysql.connect(host=u.hostname, port=u.port or 3306,
                                   user=u.username, password=u.password,
                                   database=u.path.lstrip("/"))
        except ImportError:
            raise RuntimeError(
                "install mysql-connector-python or pymysql for dbcheck")
    cur = conn.cursor()
    cur.execute("SELECT user, host, Super_priv FROM mysql.user WHERE Super_priv='Y'")
    supers = cur.fetchall()
    for user, host, _ in supers:
        add("DB-101", "MySQL SUPER privilege account", Severity.HIGH,
            f"db:mysql:{user}@{host}",
            f"Account '{user}'@'{host}' holds SUPER.",
            "Grant least privilege for application accounts.")
    cur.execute("SELECT user, host FROM mysql.user WHERE host='%'")
    for user, host in cur.fetchall():
        add("DB-102", "Account reachable from any host", Severity.MEDIUM,
            f"db:mysql:{user}@%",
            f"'{user}'@'%' accepts connections from anywhere.",
            "Restrict the host column to app subnets.")
    cur.execute("SHOW VARIABLES LIKE 'have_ssl'")
    row = cur.fetchone()
    if row and str(row[1]).upper() not in ("YES", "ON"):
        add("DB-103", "MySQL SSL disabled", Severity.HIGH, "db:mysql",
            "have_ssl is not enabled - plaintext wire traffic.",
            "Enable ssl with --ssl-ca/--ssl-cert or cloud provider TLS.")
    conn.close()
    return findings


def check_oracle(dsn: str) -> list[Finding]:
    """dsn: user/pass@host:1521/service (needs oracledb)."""
    try:
        import oracledb
    except ImportError:
        raise RuntimeError("install oracledb (pip install oracledb) for dbcheck")
    conn = oracledb.connect(dsn)
    findings: list[Finding] = []

    def add(rule, title, sev, loc, msg, rem):
        findings.append(Finding(rule_id=rule, title=title, severity=sev,
                                confidence="high", file=loc, line=1,
                                message=msg, remediation=rem,
                                engine="dbcheck", tags=["database", "live"]))
    cur = conn.cursor()
    cur.execute("""SELECT DISTINCT grantee FROM dba_sys_privs
                   WHERE privilege='DBA' OR privilege='SYSDBA'""")
    for (g,) in cur.fetchall():
        if g not in ("SYS", "SYSTEM", "SYSDBA", "DBA"):
            add("DB-201", "Account holding DBA/SYSDBA", Severity.HIGH,
                f"db:oracle:{g}", f"Grantee '{g}' holds DBA-level privilege.",
                "Revoke DBA from app accounts; use fine-grained grants.")
    cur.execute("""SELECT owner, table_name FROM dba_tables t
                   WHERE NOT EXISTS (
                     SELECT 1 FROM dba_policies p
                     WHERE p.object_owner=t.owner AND p.object_name=t.table_name)
                     AND owner NOT IN ('SYS','SYSTEM','ORDDATA','CTXSYS','XDB')""")
    rows = cur.fetchall()
    if len(rows) > 20:
        add("DB-202", "No VPD policies on user tables", Severity.MEDIUM,
            "db:oracle",
            f"{len(rows)} user tables lack VPD (fine-grained access) policies.",
            "Add VPD/RLS policies for tenant-isolated tables.")
    conn.close()
    return findings


def check(dsn: str) -> list[Finding]:
    if dsn.startswith(("postgres", "//")) or "host=" in dsn:
        return check_postgres(dsn)
    if dsn.startswith("mysql"):
        return check_mysql(dsn)
    return check_oracle(dsn)  # user/pass@host:service form

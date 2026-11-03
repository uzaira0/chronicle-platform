// ruleid: sql-exception-as-cause-java
class Mutation { void persist() { try { write(); } catch (SQLException problem) { throw new IllegalStateException("retry", problem); } } }

// ok: sql-exception-as-cause-java
class Mutation { void persist() { try { write(); } catch (SQLException problem) { throw SqlFailures.sanitize(problem); } } }


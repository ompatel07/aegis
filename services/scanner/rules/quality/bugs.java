class Bugs {
  String pick(String s) {
    // ruleid: aegis-bug-java-string-literal-equality
    if (s == "admin") return "a";
    // ok: aegis-bug-java-string-literal-equality
    if (s.equals("admin")) return "b";
    return s;
  }
  int f() {
    try {
      risky();
    } finally {
      cleanup();
      // ruleid: aegis-bug-return-in-finally-java
      return 1;
    }
  }
  void okNestedLambda() {
    try { risky(); }
    // ok: aegis-bug-return-in-finally-java
    finally { exec.submit(() -> { return 1; }); }
  }
}

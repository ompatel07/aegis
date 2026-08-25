class Bugs {
  String pick(String s, boolean flag) {
    // ruleid: aegis-bug-java-string-literal-equality
    if (s == "admin") return "a";
    // ok: aegis-bug-java-string-literal-equality
    if (s.equals("admin")) return "b";


    return s;
  }
  int f() {
    // ruleid: aegis-bug-return-in-finally
    try {
      risky();
    } finally {
      cleanup();
      return 1;
    }
  }
}

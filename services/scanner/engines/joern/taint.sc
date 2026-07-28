/*
 * Aegis Joern taint query.
 *
 * Loads a CPG produced by joern-parse and reports interprocedural taint flows
 * from HTTP-input sources to dangerous sinks for five vuln classes. Emits JSON
 * ({"findings":[...]}) matching the schema joern_engine._parse_output expects.
 *
 * Invoked as:
 *   joern --script taint.sc --param cpgFile=<cpg.bin> --param outFile=<out.json>
 *
 * The whole body is defensively wrapped so a query error still writes valid
 * (possibly empty) JSON rather than leaving the engine with no output.
 */
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, CfgNode}
import java.nio.file.{Files, Paths}
import java.nio.charset.StandardCharsets

@main def exec(cpgFile: String, outFile: String): Unit = {
  def quote(s: String): String = {
    val escaped = Option(s).getOrElse("")
      .replace("\\", "\\\\").replace("\"", "\\\"")
      .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    "\"" + escaped + "\""
  }

  val json =
    try {
      importCpg(cpgFile)
      implicit val ec: EngineContext = EngineContext()

      // Sources: values originating from an HTTP request.
      def sources =
        cpg.call.code("(?i).*(getparameter|getheader|getquerystring|getcookies)\\b.*") ++
          cpg.call.code("(?i).*\\b(req|request|ctx)\\.(query|body|params|cookies|headers)\\b.*") ++
          cpg.identifier.code("(?i).*\\b(req|request)\\.(query|body|params|cookies|headers)\\b.*")

      def sinks(rx: String) = cpg.call.code("(?i)" + rx)

      val classes = List(
        ("sql-injection", "CWE-89", "critical",
          ".*(\\.query|\\.execute|executequery|executeupdate|preparestatement|\\.raw)\\s*\\(.*"),
        ("command-injection", "CWE-78", "critical",
          ".*(child_process\\.exec|\\bexecsync|\\bexec\\s*\\(|\\bspawn\\s*\\(|os\\.system|\\.popen|getruntime\\(\\)\\.exec|processbuilder).*"),
        ("xss", "CWE-79", "high",
          ".*(res\\.(send|write|end)\\s*\\(|\\.innerhtml|document\\.write|getwriter\\(\\)\\.(print|write)).*"),
        ("ssrf", "CWE-918", "high",
          ".*(axios\\.(get|post)|\\bfetch\\s*\\(|http\\.(get|request)|urlopen|requests\\.(get|post)|new\\s+url\\s*\\(|httpget).*"),
        ("path-traversal", "CWE-22", "high",
          ".*(readfile|readfilesync|writefile|createreadstream|sendfile|\\bopen\\s*\\(|os\\.open|new\\s+file\\s*\\(|fileinputstream).*")
      )

      // Path elements are AstNodes; `.location` is the version-stable way to get
      // file + line (the older `.file.name` traversal no longer type-checks on
      // the AstNode elements a flow yields).
      def stepJson(n: AstNode): String = {
        val loc = n.location
        val file = Option(loc.filename).getOrElse("")
        val line = loc.lineNumber.map(_.toString).getOrElse("null")
        s"""{"file":${quote(file)},"line":${line},"code":${quote(n.code)}}"""
      }

      val findings = classes.flatMap { case (vulnClass, cwe, sev, rx) =>
        sinks(rx).reachableByFlows(sources).map { path =>
          val els = path.elements
          val sink = els.last
          val file = Option(sink.location.filename).getOrElse("")
          val line = sink.location.lineNumber.map(_.toString).getOrElse("null")
          val flow = els.map(stepJson).mkString("[", ",", "]")
          s"""{"vulnClass":${quote(vulnClass)},"cwe":${quote(cwe)},"severity":${quote(sev)},""" +
            s""""file":${quote(file)},"lineStart":${line},"lineEnd":${line},""" +
            s""""message":${quote(s"Untrusted request data reaches a $vulnClass sink")},"flow":${flow}}"""
        }.l
      }

      "{\"findings\":[" + findings.mkString(",") + "]}"
    } catch {
      case e: Throwable =>
        System.err.println("aegis taint query failed: " + e.getMessage)
        "{\"findings\":[]}"
    }

  Files.write(Paths.get(outFile), json.getBytes(StandardCharsets.UTF_8))
  println(s"aegis: wrote findings to $outFile")
}

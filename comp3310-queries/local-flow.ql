/**
 * @name Local flow
 * @kind path-problem
 * @problem.severity warning
 * @id java/example/local-flow
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

class UnsafeInput extends MethodAccess{
  UnsafeInput() {
    (this.getMethod().hasName("nextLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.util","Scanner"))
 	or 
 	(this.getMethod().hasName("readLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.io","BufferedReader"))
  }
}

class PrepareStmt extends MethodAccess {
  PrepareStmt() { this.getMethod().hasName("prepareStatement") and
     this.getMethod().getDeclaringType().hasQualifiedName("java.sql","Connection")
  }
}

from UnsafeInput source, VarAccess sink
where 
exists(PrepareStmt p| p.getArgument(0)=sink) and
TaintTracking::localTaint(DataFlow::exprNode(source), DataFlow::exprNode(sink))
select sink.getNode(), source, sink, "Possible flow of untrusted input"

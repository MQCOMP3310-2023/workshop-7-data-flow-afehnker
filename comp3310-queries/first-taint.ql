/**
 * @name First Taint
 * @kind problem
 * @problem.severity warning
 * @id java/example/first-taint
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
from UnsafeInput source, VarAccess sink
where TaintTracking::localTaint(DataFlow::exprNode(source), DataFlow::exprNode(sink))
select source, sink

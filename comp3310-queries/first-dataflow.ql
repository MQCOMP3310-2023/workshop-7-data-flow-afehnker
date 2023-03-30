/**
 * @name First data flow example
 * @kind problem
 * @problem.severity warning
 * @id java/example/source-sink
 */


import java
import semmle.code.java.dataflow.DataFlow

class UnsafeInput extends MethodAccess{
  UnsafeInput() {
    (this.getMethod().hasName("nextLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.util","Scanner"))
 	or 
 	(this.getMethod().hasName("readLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.io","BufferedReader"))
  }
}
from UnsafeInput source, VarAccess sink
where DataFlow::localFlow(DataFlow::exprNode(source), DataFlow::exprNode(sink))
select source, "From this source", sink, "To this sink"

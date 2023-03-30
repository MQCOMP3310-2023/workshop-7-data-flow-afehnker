/**
 * @name Global flow
 * @kind path-problem
 * @problem.severity warning
 * @id java/example/global-flow
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class UnsafeInput extends MethodAccess{
  UnsafeInput() {
    (this.getMethod().hasName("nextLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.util","Scanner"))
 	or 
 	(this.getMethod().hasName("readLine") and this.getMethod().getDeclaringType().hasQualifiedName("java.io","BufferedReader"))
  }
}

class MyConfig extends TaintTracking::Configuration {
  MyConfig(){
    this = "MyConfig"
  }
  
  override predicate isSource(DataFlow::Node source) {
    exists(UnsafeInput ma| ma = source.asExpr())   
  }
  
  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma| ma.getArgument(0) = sink.asExpr())    
  }
}

from   MyConfig globalFlow, DataFlow::PathNode source, DataFlow::PathNode sink
where  
globalFlow.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Possible flow of untrusted input"

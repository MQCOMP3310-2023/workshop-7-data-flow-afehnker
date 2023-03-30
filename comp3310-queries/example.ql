/**
 * @name Comp3310 workshop 6 query
 * @kind problem
 * @problem.severity warning
 * @id java/example/empty-block
 */


 import java

 from LoopStmt loop,  MethodAccess callPrint
 where
     loop.getAChild*() = callPrint.getEnclosingStmt() and  
       callPrint.getMethod().hasName("println") and
       callPrint.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintStream") and
       not exists(MethodAccess callScan|
           loop.getAChild*() = callScan.getEnclosingStmt() and 
           callScan.getMethod().hasName("nextLine") and
           callScan.getMethod().getDeclaringType().hasQualifiedName("java.util", "Scanner")
       )
 select callPrint, "This prints in a loop without a scanner."
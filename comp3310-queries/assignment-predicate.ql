/**
 * @name Assignment predicate example
 * @kind problem
 * @problem.severity warning
 * @id java/example/assignment-predicate
 */


import java

 predicate inAssignment(Expr e){
   exists (AssignExpr a| a.getAChildExpr*() = e) 
 }
 
 from MethodAccess call
 where inAssignment(call)
 select call, "Used in an assignment."

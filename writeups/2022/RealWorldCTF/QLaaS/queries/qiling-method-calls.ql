// See:
// https://github.com/github/codeql/blob/main/python/ql/examples/snippets/method_call.ql

import python

from AstNode call, PythonFunctionValue method
where
    method.getQualifiedName().matches("%ql%") and
    method.getACall().getNode() = call
select call, method.getQualifiedName()
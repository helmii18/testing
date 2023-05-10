import ast

# Define the function to detect bugs
def detect_bugs(x):
    # Parse the code string into an AST
    try:
        module = ast.parse(ast.NodeVisitor(x))
    except SyntaxError as e:
        return f"Syntax error: {e}"

    # Check for bugs in the AST
    bugs = []

    # Bug 1: Check for undefined variables
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if not any(isinstance(parent, ast.FunctionDef) for parent in ast.iter_parent_nodes(node)):
                bugs.append(f"Undefined variable: {node.id}")

    # Bug 2: Check for unreachable code
    for node in ast.walk(module):
        if isinstance(node, ast.Expr) and not isinstance(node.value, (ast.Constant, ast.NameConstant)):
            bugs.append("Unreachable code")

    # Bug 3: Check for syntax errors
    for node in ast.walk(module):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func,
                                                                                          ast.Name) and node.value.func.id == "print":
            if len(node.value.args) == 0:
                bugs.append("Syntax error: Empty print statement")

    # Bug 4: Check for unused variables
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if not any(isinstance(parent, (ast.Assign, ast.FunctionDef, ast.arg)) for parent in
                       ast.iter_parent_nodes(node)):
                bugs.append(f"Unused variable: {node.id}")

    # Bug 5: Check for incorrect function signatures
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef):
            if len(node.args.args) > 0 and node.args.args[0].arg != "self":
                bugs.append("Incorrect function signature")

    # Bug 6: Check for incorrect indentation
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            for stmt in node.body:
                if not isinstance(stmt, (ast.Pass, ast.Expr)):
                    if not isinstance(stmt, ast.If):
                        if not isinstance(stmt, ast.Return) or stmt.value is not None:
                            if stmt.col_offset != node.col_offset + 4:
                                bugs.append("Incorrect indentation")

    # Bug 7: Check for incorrect boolean logic
    for node in ast.walk(module):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            if isinstance(node.values[0], ast.Constant) and isinstance(node.values[1], ast.Constant):
                if node.op.__class__(node.values[0].value, node.values[1].value).value != node.values[
                    0].value or node.op.__class__(node.values[0].value, node.values[1].value).value != node.values[
                    1].value:
                    bugs.append("Incorrect boolean logic")


    # Bug 8: Check for incorrect variable assignments
    for node in ast.walk(module):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Div) and isinstance(
                    node.value.right, ast.Num) and node.value.right.n == 0:
                bugs.append("Incorrect variable assignment")
    # Bug 9: Check for incorrect use of class inheritance
    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef) and len(node.bases) > 0:
            for base in node.bases:
                if isinstance(base, ast.Attribute) and isinstance(base.value,
                                                                  ast.Name) and base.value.id == "os" and base.attr == "Path":
                    bugs.append("Incorrect use of class inheritance")
    # Bug 10: Check for inconsistent return types
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.returns is not None:
            for return_node in ast.walk(node):
                if isinstance(return_node, ast.Return) and return_node.value is not None:
                    if isinstance(node.returns, ast.NameConstant) and isinstance(return_node.value,
                                                                                 ast.Constant) and node.returns.value != return_node.value.value:
                        bugs.append("Inconsistent return types")
                    elif isinstance(node.returns, ast.Name) and isinstance(return_node.value,
                                                                           ast.Name) and node.returns.id != return_node.value.id:
                        bugs.append("Inconsistent return types")

    # Bug 11: Check for infinite loops
    for node in ast.walk(module):
        if isinstance(node, ast.While) and isinstance(node.test,
                                                      ast.Constant) and node.test.value == True:
            bugs.append("Infinite loop")

    # Bug 12: Check for incorrect loop conditions
    for node in ast.walk(module):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Call) and isinstance(node.iter.func,
                                                                                        ast.Name) and node.iter.func.id == "range":
            if len(node.iter.args) == 1 and isinstance(node.iter.args[0], ast.Num) and node.iter.args[
                0].n > 0:
                if isinstance(node.body[-1], ast.If) and isinstance(node.body[-1].test,
                                                                    ast.Compare) and len(
                        node.body[-1].test.ops) == 1 and isinstance(node.body[-1].test.ops[0], ast.Gt):
                    if isinstance(node.body[-1].test.left, ast.Name) and node.body[
                        -1].test.left.id == node.target.id:
                        if isinstance(node.body[-1].test.comparators[0], ast.Num) and \
                                node.body[-1].test.comparators[0].n == node.iter.args[0].n:
                            bugs.append("Incorrect loop condition")

    # Bug 13: Check for incorrect list slicing
    for node in ast.walk(module):
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            if node.slice.upper is None and node.slice.lower is None and node.slice.step is None:
                if isinstance(node.value, ast.List) and len(node.value.elts) > 0:
                    bugs.append("Incorrect list slicing")

    # Bug 14: Check for incorrect exception handling
    for node in ast.walk(module):
        if isinstance(node, ast.Try):
            if isinstance(node.body[-1], ast.Raise) and node.handlers == []:
                bugs.append("Incorrect exception handling")

    # Bug 15: Check for incorrect dictionary initialization
    for node in ast.walk(module):
        if isinstance(node, ast.Dict) and len(node.keys) > 0:
            for key_node in node.keys:
                if not isinstance(key_node, ast.Constant):
                    bugs.append("Incorrect dictionary initialization")

    # Bug 16: Check for incorrect boolean comparisons
    for node in ast.walk(module):
        if isinstance(node, ast.Compare) and isinstance(node.ops[0], ast.Eq):
            if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
                if isinstance(node.left.value, bool) and isinstance(node.right.value,
                                                                    bool) and node.left.value == node.right.value:
                    bugs.append("Incorrect boolean comparison")

    # Bug 17: Check for incorrect list comprehension syntax
    for node in ast.walk(module):
        if isinstance(node, ast.ListComp) and len(node.generators) > 0:
            for gen_node in node.generators:
                if isinstance(gen_node.target, ast.Name) and isinstance(gen_node.iter, ast.Call) and isinstance(
                        gen_node.iter.func, ast.Name) and gen_node.iter.func.id == "range":
                    if len(gen_node.iter.args) == 1 and isinstance(gen_node.iter.args[0], ast.Num) and \
                            gen_node.iter.args[0].n > 0:
                        if isinstance(gen_node.ifs[0], ast.Compare) and len(gen_node.ifs[0].ops) == 1 and isinstance(
                                gen_node.ifs[0].ops[0], ast.Gt):
                            if isinstance(gen_node.ifs[0].left, ast.Name) and gen_node.ifs[
                                0].left.id == gen_node.target.id:
                                if isinstance(gen_node.ifs[0].comparators[0], ast.Num) and gen_node.ifs[0].comparators[
                                    0].n == gen_node.iter.args[0].n:
                                    bugs.append("Incorrect list comprehension syntax")

    # Bug 18: Check for incorrect use of global keyword
    for node in ast.walk(module):
        if isinstance(node, ast.Global) and len(node.names) > 0:
            for name in node.names:
                if name != "global_var":
                    bugs.append("Incorrect use of global keyword")

    # Bug 19: Check for incorrect use of with statement
    for node in ast.walk(module):
        if isinstance(node, ast.With) and len(node.items) > 0:
            for item in node.items:
                if isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func,
                                                                          ast.Name) and item.context_expr.func.id == "open":
                    if isinstance(item.optional_vars, ast.Name) and item.optional_vars.id != "file":
                        bugs.append("Incorrect use of with statement")



    return bugs


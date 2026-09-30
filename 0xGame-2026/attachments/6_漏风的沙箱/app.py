import ast
import builtins
import io
import os
import re
import threading
import traceback
import unicodedata
from contextlib import redirect_stdout

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SANDBOX_TIMEOUT = int(os.environ.get('SANDBOX_TIMEOUT', '5'))
MAX_CODE_LEN = 5000
MAX_OUTPUT_LEN = 100000
PORT = int(os.environ.get('PORT', '18085'))

dangerous_patterns = [
    r'\bos\.system\b',
    r'\bos\.popen\b',
    r'\bos\.spawn\b',
    r'\bos\.exec\b',
    r'\bos\.fork\b',
    r'\bsubprocess\b',
    r'\bcommands\b',
    r'\b__import__\s*\(',
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bcompile\s*\(',
    r'\bopen\s*\(',
    r'\bfile\s*\(',
    r'\b__builtins__\b',
    r'\bimport\s+os\b',
    r'\bimport\s+sys\b',
    r'\bimport\s+subprocess\b',
    r'\bimport\s+pymysql\b',
    r'\bimport\s+sqlite3\b',
    r'\bimport\s+requests\b',
    r'\bimport\s+urllib\b',
    r'\bimport\s+http\b',
    r'\bimport\s+socket\b',
    r'\bimport\s+ftplib\b',
    r'\bimport\s+telnetlib\b',
    r'\bimport\s+pickle\b',
    r'\bimport\s+cpickle\b',
    r'\bimport\s+marshal\b',
    r'\bimport\s+ctypes\b',
    r'\bimport\s+multiprocessing\b',
    r'\bimport\s+threading\b',
    r'\bimport\s+concurrent\b',
    r'\bimport\s+io\b',
    r'\bimport\s+shlex\b',
    r'\bimport\s+pty\b',
    r'\bimport\s+popen\b',
    r'\bimport\s+shutil\b',
    r'\bimport\s+platform\b',
    r'\bimport\s+cffi\b',
    r'\bimport\s+importlib\b',
    r'\bgetattr\s*\(.*__import__',
    r'\bgetattr\s*\(.*eval',
    r'\bgetattr\s*\(.*exec',
    r'\bsetattr\s*\(',
    r'\b__getattribute__\b',
    r'\b__setattr__\b',
]
COMPILED_PATTERNS = [re.compile(p) for p in dangerous_patterns]

BANNED_MODULES = [
    'os', 'sys', 'subprocess', 'pymysql', 'sqlite3',
    'requests', 'urllib', 'http', 'socket', 'ftplib', 'telnetlib',
    'pickle', 'cpickle', 'marshal', 'ctypes',
    'multiprocessing', 'threading', 'concurrent',
    'importlib', 'imp', 'builtins',
    'shlex', 'pty', 'popen', 'shutil', 'platform', 'cffi', 'io',
]

BANNED_FUNCTIONS = [
    'eval', 'exec', 'compile', '__import__',
    'getattr', 'setattr', 'delattr',
    'globals', 'locals', 'vars', 'dir', 'type',
    'input', 'open', 'file', 'execfile', 'reload',
]

BANNED_METHODS = [
    'system', 'popen', 'spawn', 'execv', 'execl', 'execve', 'execlp', 'execvp',
    'chdir', 'kill', 'remove', 'unlink', 'rmdir', 'mkdir', 'makedirs', 'removedirs',
    'read', 'write', 'readlines', 'writelines',
    'load', 'loads', 'dump', 'dumps',
    'get_data', 'get_source', 'get_code', 'load_module', 'exec_module',
]

DANGEROUS_ATTRIBUTES = [
    '__class__', '__base__', '__bases__', '__mro__', '__subclasses__',
    '__globals__', '__builtins__', '__getattribute__', '__getattr__',
    '__setattr__', '__delattr__', '__call__',
]


class FilterError(Exception):
    pass


class ASTFilter(ast.NodeVisitor):
    def visit_Import(self, node):
        for alias in node.names:
            raise FilterError()
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        raise FilterError()

    def visit_Attribute(self, node):
        if node.attr in DANGEROUS_ATTRIBUTES:
            raise FilterError()
        if node.attr in BANNED_METHODS:
            raise FilterError()
        if node.attr in BANNED_FUNCTIONS:
            raise FilterError()
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in BANNED_FUNCTIONS:
            raise FilterError()
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
            key = node.slice.value
            if key in DANGEROUS_ATTRIBUTES or key in BANNED_METHODS \
                    or key in BANNED_FUNCTIONS or key in BANNED_MODULES:
                raise FilterError()
        self.generic_visit(node)


def _sandbox_builtins():
    b = dict(builtins.__dict__)
    b.pop('breakpoint', None)
    b.pop('input', None)
    return b


SANDBOX_BUILTINS = _sandbox_builtins()


def run_sandbox(code):
    code = unicodedata.normalize('NFKC', code)

    for pattern in COMPILED_PATTERNS:
        if pattern.search(code):
            return {'status': 'blocked', 'output': ''}

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {'status': 'blocked', 'output': ''}

    visitor = ASTFilter()
    try:
        visitor.visit(tree)
    except FilterError:
        return {'status': 'blocked', 'output': ''}

    sandbox = {'__builtins__': dict(SANDBOX_BUILTINS)}
    buf = io.StringIO()
    result = {}

    def _exec():
        try:
            with redirect_stdout(buf):
                exec(code, sandbox)
            result['output'] = buf.getvalue()
        except SystemExit:
            result['error'] = 'SystemExit'
        except BaseException:
            result['error'] = traceback.format_exc()

    worker = threading.Thread(target=_exec, daemon=True)
    worker.start()
    worker.join(SANDBOX_TIMEOUT)
    if worker.is_alive():
        return {'status': 'timeout', 'output': ''}

    if 'error' in result:
        return {'status': 'error',
                'output': (buf.getvalue() + '\n' + result['error'])[:MAX_OUTPUT_LEN]}

    output = result.get('output', '')
    if len(output) > MAX_OUTPUT_LEN:
        output = output[:MAX_OUTPUT_LEN]
    return {'status': 'ok', 'output': output}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/run', methods=['POST'])
def run():
    data = request.get_json(silent=True) or {}
    code = data.get('code', '')
    if not isinstance(code, str) or not code.strip():
        return jsonify({'status': 'ok', 'output': ''})
    if len(code) > MAX_CODE_LEN:
        return jsonify({'status': 'blocked', 'output': ''})
    return jsonify(run_sandbox(code))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)

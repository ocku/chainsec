import base64

payload = base64.b64decode("cHJpbnQoJ29rJyk=")
second = base64.decodebytes(b"cHJpbnQoJ29rJyk=")
compiled = compile(payload, "<fixture>", "exec")
eval("1 + 1")
exec(compiled)

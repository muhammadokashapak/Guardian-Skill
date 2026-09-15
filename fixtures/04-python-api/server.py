import pickle
import os
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/deserialize")
async def unsafe_deserialize(req: Request):
    data = await req.body()
    # VULNERABILITY: Unsafe pickle deserialization
    obj = pickle.loads(data)
    return {"status": "ok", "type": str(type(obj))}

@app.get("/ping")
def ping_host(host: str):
    # VULNERABILITY: Command Injection
    cmd = f"ping -c 1 {host}"
    os.system(cmd)
    return {"status": "pinged"}

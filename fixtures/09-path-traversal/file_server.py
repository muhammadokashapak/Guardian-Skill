from fastapi import FastAPI

app = FastAPI()

@app.get("/read")
def read_file(filename: str):
    # Unsanitized path concatenation
    with open(f"./uploads/{filename}", "r") as f:
        return f.read()

from fastapi import FastAPI

from app.routers import auth, admin
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def hello():
    return {"message": "Hello, World!"}


app.include_router(auth.router)
app.include_router(admin.router)

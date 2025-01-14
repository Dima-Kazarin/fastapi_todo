from typing import List, Optional

import bcrypt
from authx import AuthX, AuthXConfig
from fastapi import FastAPI, HTTPException, Response, Depends, Request
from sqlalchemy import select, update
import jwt
from database import SessionDep, Base, engine, User, Task
from schemas import UserCreate, User as DbUser, TaskCreate, Task as DbTask, TaskUpdate, UserLoginSchema

app = FastAPI()

config = AuthXConfig()
config.JWT_SECRET_KEY = 'SECRET_KEY'
config.JWT_ACCESS_COOKIE_NAME = 'access_token'
config.JWT_REFRESH_COOKIE_NAME = 'refresh_token'
config.JWT_TOKEN_LOCATION = ['cookies']

security = AuthX(config=config)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


@app.post('/login')
async def login(user: UserLoginSchema, session: SessionDep, response: Response):
    user1 = await session.scalar(select(User).where(User.name == user.name))
    if verify_password(user.password, user1.password):
        access_token = security.create_access_token(uid=str(user1.id))
        response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, access_token)

        refresh_token = security.create_refresh_token(uid=str(user1.id))
        response.set_cookie(config.JWT_REFRESH_COOKIE_NAME, refresh_token, httponly=True, secure=True,
                            max_age=60 * 60 * 24 * 7)

        return {'access_token': access_token, 'refresh_token': refresh_token}
    raise HTTPException(status_code=401, detail='Incorrect username or password')


def get_refresh_token(request: Request):
    refresh_token = request.cookies.get(config.JWT_REFRESH_COOKIE_NAME)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found")
    return refresh_token


@app.post('/refresh_token')
async def token_refresh(response: Response, refresh_token: str = Depends(get_refresh_token)):
    try:
        decoded_token = jwt.decode(refresh_token)
        user_id = decoded_token['sub']

        access_token = security.create_access_token(uid=user_id)
        response.set_cookie(config.JWT_ACCESS_COOKIE_NAME, access_token)
        return {'access_token': access_token}

    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid refresh token: {str(e)}")


@app.post('/setup_database')
async def async_main():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.post('/users', response_model=DbUser)
async def create_user(user: UserCreate, session: SessionDep):
    hashed_password = hash_password(user.password)
    new_user = User(name=user.name, password=hashed_password)

    session.add(new_user)
    await session.commit()

    return new_user


@app.post('/tasks', response_model=DbTask)
async def create_task(task: TaskCreate, session: SessionDep):
    db_user = await session.scalar(select(User).where(User.id == task.user_id))
    if not db_user:
        raise HTTPException(status_code=400, detail='Bad request')

    new_task = Task(title=task.title, description=task.description, user_id=task.user_id)

    session.add(new_task)
    await session.commit()

    return new_task


@app.get('/users', response_model=List[DbUser])
async def get_users(session: SessionDep):
    return await session.scalars(select(User))


@app.get('/tasks', response_model=List[DbTask])
async def get_tasks(session: SessionDep, is_done: Optional[bool] = None):
    if is_done is not None:
        tasks = await session.scalars(select(Task).where(Task.is_done == is_done))
    else:
        tasks = await session.scalars(select(Task))
    return tasks


@app.get('/users/{id}', response_model=DbUser)
async def get_user_by_id(id: int, session: SessionDep):
    return await session.scalar(select(User).where(User.id == id))


@app.get('/tasks/{id}', response_model=DbTask)
async def get_task_by_id(id: int, session: SessionDep):
    return await session.scalar(select(Task).where(Task.id == id))


@app.put('/tasks/{id}', response_model=DbTask)
async def update_task(id: int, task: TaskUpdate, session: SessionDep):
    is_task = await session.scalar(select(Task).where(Task.id == id))

    if is_task:
        await session.execute(update(Task).where(Task.id == id).values(title=task.title, description=task.description,
                                                                       is_done=task.is_done, user_id=task.user_id))
        await session.commit()
        return is_task
    raise HTTPException(status_code=400, detail='Task not found')


@app.put('/tasks/status/{id}', response_model=DbTask)
async def update_task_status(id: int, session: SessionDep):
    task = await session.scalar(select(Task).where(Task.id == id))

    if task:
        task.is_done = False if task.is_done else True
        await session.commit()
        return task
    raise HTTPException(status_code=400, detail='Task not found')


@app.delete('/tasks/{id}')
async def delete_task(id: int, session: SessionDep):
    task = await session.scalar(select(Task).where(Task.id == id))

    if task:
        await session.delete(task)
        await session.commit()

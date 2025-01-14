from pydantic import BaseModel


class UserLoginSchema(BaseModel):
    name: str
    password: str


class UserBase(BaseModel):
    name: str
    password: str


class UserCreate(UserBase):
    pass


class User(UserBase):
    id: int

    class Config:
        orm_mode = True


class TaskBase(BaseModel):
    title: str
    description: str
    is_done: bool
    user_id: int


class TaskCreate(BaseModel):
    title: str
    description: str
    user_id: int


class TaskUpdate(TaskBase):
    pass


class Task(TaskBase):
    id: int

    class Config:
        orm_mode = True

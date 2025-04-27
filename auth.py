import bcrypt
from database import create_user, get_user_by_username

def signup(username:str, password:str):
    user = get_user_by_username(username)
    if user:
        print("Username already exists.")
        return False
    hashed_pwd = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    create_user(username,hashed_pwd)
    print("Signup Successful")
    return True

def login(username:str, password:str):
    user = get_user_by_username(username)
    if not user:
        print("User not found.")
        return None
    if bcrypt.checkpw(password.encode(), user['password']):
        print("Login Successful!")
        return user
    else:
        print("Invalid Password.")
        return None
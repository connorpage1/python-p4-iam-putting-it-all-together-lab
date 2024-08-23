from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)
    
    recipes = db.relationship("Recipe", back_populates="user", cascade='all, delete-orphan')
    
    serialize_rules = ('-recipes', '-_password_hash')
    
    def __init__(self, username=None, password=None, **kwargs):
        super().__init__(username=username, **kwargs)
        if password:
            self.password_hash = password
        

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Passwords are private")
    
    @password_hash.setter
    def password_hash(self, new_pw):
        hashed_pw = bcrypt.generate_password_hash(new_pw).decode("utf-8")
        self._password_hash = hashed_pw
    
    def authenticate(self, pw_to_check):
        return bcrypt.check_password_hash(self._password_hash, pw_to_check)

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    user = db.relationship("User", back_populates='recipes')
    
    serialize_rules = ('-user.recipes', )
    
    @validates('instructions')
    def validate_instructions(self, _, instructions):
        # if not isinstance(instructions, str):
        #     raise TypeError("Instructions must be a string")
        if  len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long ")
        return instructions 
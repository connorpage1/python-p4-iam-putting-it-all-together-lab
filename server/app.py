#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        try:
            data = request.get_json()
            user = User(**data)
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        try:
            if 'user_id' not in session:
                return {'errors': 'User not signed in'}, 401
            user = db.session.get(User, session.get("user_id"))
            return user.to_dict(), 200
        except Exception as e:
            return {'errors': str(e)}, 401

class Login(Resource):
    def post(self):
        try:
            data =  request.get_json()
            query = db.select(User).where(User.username == data.get('username'))
            user = db.session.scalars(query).first()
            
            if user and user.authenticate(data.get('password')):
                session['user_id'] = user.id
                return user.to_dict(), 200
            return {'error': 'Invalid credentials'}, 401
        except Exception as e:
            return {'error': str(e)}, 401
            
class Logout(Resource):
    def delete(self):
        try:
            if session.get("user_id"):
                del session['user_id']
                return {}, 204
            else: 
                return {'error': 'Not logged in'}, 401
        except Exception as e:
            return {'error': str(e)}, 401

class RecipeIndex(Resource):    
    def get(self):
        # Check if the user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)

        # Retrieve all recipes
        recipes = Recipe.query.all()
        recipe_list = [
            {
                'id': recipe.id,
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username
                }
            }
            for recipe in recipes
        ]
        return make_response(recipe_list, 200)

    def post(self):
        # Check if the user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)

        # Extract data from the request
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        # Validate the data
        if not title or not instructions or len(instructions) < 50:
            return make_response({'error': 'Invalid data'}, 422)

        # Create a new recipe associated with the logged-in user
        new_recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=user_id
        )

        # Add and commit the new recipe to the database
        db.session.add(new_recipe)
        db.session.commit()

        # Return the created recipe as a JSON response
        return make_response({
            'id': new_recipe.id,
            'title': new_recipe.title,
            'instructions': new_recipe.instructions,
            'minutes_to_complete': new_recipe.minutes_to_complete,
            'user': {
                'id': new_recipe.user.id,
                'username': new_recipe.user.username
            }
        }, 201)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
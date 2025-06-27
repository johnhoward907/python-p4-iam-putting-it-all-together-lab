#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from flask import jsonify

from config import app, db, api
from models import User, Recipe

class Users(Resource):
    def get(self):
        users = User.query.all()
        return [user.to_dict() for user in users], 200


class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        try:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = password

            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id

            return user.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username must be unique."]}, 422
        except ValueError as e:
            return {"errors": [str(e)]}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
        return {"error": "Unauthorized"}, 401


class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session["user_id"] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401
    


class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session.pop("user_id")
            return {}, 204
        return {"error": "Unauthorized"}, 401


class RecipeIndex(Resource):
    def get(self):
        if not session.get("user_id"):
            return {"error": "Unauthorized"}, 401

        recipes = Recipe.query.all()
        return [r.to_dict() for r in recipes], 200

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        title = data.get("title")
        instructions = data.get("instructions")
        minutes_to_complete = data.get("minutes_to_complete")

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201
        except ValueError as e:
            return {"errors": [str(e)]}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')
api.add_resource(Users, '/users', endpoint='users')



@app.route('/')
def index():
    return jsonify({
        "message": "Welcome to the Flask API",
        "routes": [
            "/signup",
            "/login",
            "/logout",
            "/check_session",
            "/recipes"
        ]
    })

if __name__ == '__main__':
    app.run(port=5555, debug=True)
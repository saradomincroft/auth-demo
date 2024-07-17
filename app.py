from config import app, api
from flask import make_response, session, request
from flask_migrate import Migrate
from models import db, User
from flask_restful import Resource

@app.route('/')
def index():
    return make_response( {"message": "Welcome!"}, 200)

# @app.before_request - remove decorator handling checking on front
# will exeute whatever method we definie here bfore
def authenticate():
    # exempted_endpoints = ['signup', 'login'] 
    # use routes instead
    exempted_routes = {
        "/" : ["GET"],
        "/signup" : ["POST"],
        "/login" : ["POST"],
        "/me": ["GET"]
    }

    # if request.endpoint in exempted_endpoints:
    if request.path in exempted_routes:
        allowed_methods = exempted_routes[request.path]

        if request.method in allowed_methods:
            return None

    if 'user' not in session:
        return make_response({"error": "Unauthorised..."}, 403)

    # if 'user' not in session and request.endpoint not in exempted_endpoints:
    #     return make_response({"error": "Unauthorisez..."}, 403)
    # potential problem here
    # if sign up new user also getting unauth message
    # need to make exceptions 
    # add endpoints to resource (below bottom)
    # exepmt endpoiunts


class Signup(Resource):
    def post(self):
        user = User(username=request.json.get('username'), hashed_password=request.json.get('password'), is_admin=request.json.get('is_admin'))

        db.session.add(user)
        db.session.commit()

        if user.id:
            session['user_id'] = user.id # storing into session var (changed same as below)
            # to_dict() make it json 

            # return make_response( {"message": "User account created..."}, 201)
            return make_response( user.to_dict(), 201)
        
        return make_response({"error": "Unsuccessful"}, 400)


class Login(Resource):
    def post(self):
        user = User.query.filter(User.username == request.json.get('username')).first()

        if user and user.authenticate(request.json.get('password')):
            session['user_id'] = user.id # just storing user id so doesnt store other info about user (before was just user and user to_dict())

            return make_response( user.to_dict(), 200)

        return make_response({"error": "Unauthorised"}, 403)


class Logout(Resource): # logout must be del method
    def delete(self):
        # session['user'] = None
        session.pop('user', None)
        session.pop('user_id', None)

        return make_response( {"message" : "Logout successful..."}, 200)

class Me(Resource):
    def get(self):
        # if 'user' in session: # session['user']
        user = User.query.filter(User.id == session['user_id']).first()

        if user:
            # user = User.query.filter(User.id == session['user_id']).first()
            return make_response(user.to_dict(), 200)
        
        return make_response( {"error": "No user signed in"}, 403)


class Users(Resource):
    def get(self):
        # only admin users can access
        # if 'user' not in session:
        #     return make_response( {"error": "Forbidden"}, 403)
        user = User.query.filter(User.id == session['user_id']).first()

        # user = session['user'] 
        # if user['is_admin'] == 1:
        if user and user.is_admin == 1:
            users = [ user.to_dict() for user in User.query.all() ]

            return make_response(users, 200)
        
        return make_response( {"error": "You don't have admin access"}, 403)


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout')
api.add_resource(Me, '/me')
api.add_resource(Users, '/users')


if __name__ == "__main__":
    app.run(port=4000, debug=True)
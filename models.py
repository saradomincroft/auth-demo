from config import db, bcrypt
from sqlalchemy_serializer import SerializerMixin # so can use to_dict
from sqlalchemy.ext.hybrid import hybrid_property


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Integer, default=0) # can use boolean for this if want, for this 1 True, 0 False
    _hashed_password = db.Column(db.String) # _ for private, normally not null but already have users so skip this time

    @hybrid_property # @property
    def hashed_password(self): # user.hashed_password
        return self._hashed_password
    
    @hashed_password.setter
    def hashed_password(self, password):
        hashed_password = bcrypt.generate_password_hash( password.encode('utf-8') )

        self._hashed_password = hashed_password.decode('utf-8')
        # decoding because storing into db and they cannot accom utf8
    def authenticate(self, password):
        return bcrypt.check_password_hash( self._hashed_password, password.encode('utf-8'))


    def __repr__(self):
        return f"<User {self.id}: {self.username}>"
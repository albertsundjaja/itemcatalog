from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

deleteUsers = session.query(User).all()
deleteCategories = session.query(Category).all()
deleteItems = session.query(Item).all()

for u in deleteUsers:
    session.delete(u)
    session.commit()

for c in deleteCategories:
    session.delete(c)
    session.commit()

for i in deleteItems:
    session.delete(i)
    session.commit()

print "cleaning success"
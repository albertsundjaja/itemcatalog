from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create dummy user
User1 = User(name="Joker", email="joker@hahaha.com")
session.add(User1)
session.commit()

user1_id = session.query(User).filter_by(name="Joker").one()

# Create dummy categories
category1 = Category(user_id=1, name="Electronics")

session.add(category1)
session.commit()

category2 = Category(user_id=1, name="Cleaning Tools")

session.add(category2)
session.commit()

#create dummy item for the categories
category1_id = session.query(Category).filter_by(name="Electronics").one()
item1 = Item(user_id=user1_id.id, name="Notebook", description="A simple notebook to note stuffs", category_id=category1_id.id)

session.add(item1)
session.commit()

item2 = Item(user_id=user1_id.id, name="UHD TV", description="The TV that will zap your time away. Ha Ha", category_id=category1_id.id)
session.add(item2)
session.commit()

category2_id = session.query(Category).filter_by(name="Cleaning Tools").one()

item3 = Item(user_id=user1_id.id, name="Broom", description="Brooom broooom", category_id=category2_id.id)

session.add(item3)
session.commit()

item4 = Item(user_id=user1_id.id, name="Sponge", description="Spongy thingy", category_id=category2_id.id)

session.add(item4)
session.commit()


print "dummy data created"
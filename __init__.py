from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
import sys
sys.path.append('/var/www/html/itemcatalog/')
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('/var/www/html/itemcatalog/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"


# Connect to Database and create database session
engine = create_engine('sqlite:////var/www/html/itemcatalog/itemcatalog.db')
Base.metadata.bind = engine

DBSession = scoped_session(sessionmaker(bind=engine))
session = DBSession()


# Function implementing CSRF
def checkTokenState():
    if 'crud_state' not in login_session:
        login_session['crud_state'] = generateToken()

def generateToken():
    crud_state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    return crud_state


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


#OAuth for google+
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs
@app.route('/JSON/<int:category_id>/all')
def categoryItemJSON(category_id):
    """ fetch all items in a category """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(CategoryItems=[i.serialize for i in items])


@app.route('/JSON/<int:category_id>/<int:item_id>/')
def itemJSON(category_id, item_id):
    """ fetch a specific item by id """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/JSON/category')
def categoryJSON():
    """ fetch all categories in the catalog """
    categories = session.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])

# Show the catalog (main page)
@app.route('/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    latestItems = session.query(Item).order_by(desc(Item.id)).limit(5)
    if 'username' not in login_session:
        return render_template('publiccatalog.html', categories=categories, latestItems=latestItems)
    else:
        return render_template('catalog.html', categories=categories, latestItems=latestItems)

# Create a new category
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    checkTokenState()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        #check for CSRF attack
        crud_state = request.form['_csrf_token']
        if crud_state != login_session['crud_state']:
            return "<script>function myFunction() {alert('CSRF attack detected!');}</script><body onload='myFunction()''>"

        newCategory = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newcategory.html', crud_state = login_session['crud_state'])


# Show items inside the category
@app.route('/catalog/<int:category_id>/items/')
def showItem(category_id):
    categories = session.query(Category).order_by(asc(Category.name))
    currentCategory = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(currentCategory.user_id)
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicitem.html', items=items, categories=categories, currentCategory=currentCategory, creator=creator)
    else:
        return render_template('item.html', items=items, categories=categories, currentCategory=currentCategory, creator=creator)


# Show item description
@app.route('/catalog/<int:category_id>/items/<int:item_id>/')
def showDescription(category_id, item_id):
    categories = session.query(Category).order_by(asc(Category.name))
    currentItem = session.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(currentItem.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicitemdesc.html', categories=categories, currentItem=currentItem)
    else:
        return render_template('itemdesc.html', categories=categories, currentItem=currentItem)


# Create a new item
@app.route('/catalog/<int:category_id>/items/new/', methods=['GET', 'POST'])
def newItem(category_id):
    checkTokenState()
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add items to this category. Please create your own category.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
            #check for CSRF attack
            crud_state = request.form['_csrf_token']
            if crud_state != login_session['crud_state']:
                return "<script>function myFunction() {alert('CSRF attack detected!');}</script><body onload='myFunction()''>"

            newItem = Item(name=request.form['name'], description=request.form['description'],
                    user_id=category.user_id, category_id=category_id)
            session.add(newItem)
            session.commit()
            flash('New Item %s Successfully Created' % (newItem.name))
            return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('newitem.html', category_id=category_id, crud_state=login_session['crud_state'])


# Edit item
@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    checkTokenState()
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit items for this category.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
         #check for CSRF attack
        crud_state = request.form['_csrf_token']
        if crud_state != login_session['crud_state']:
            return "<script>function myFunction() {alert('CSRF attack detected!');}</script><body onload='myFunction()''>"

        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('edititem.html', category_id=category_id, item_id=item_id, item=editedItem,
                                crud_state=login_session['crud_state'])


# Delete item
@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    checkTokenState()
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=category_id).one()
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete items for this category.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
         #check for CSRF attack
        crud_state = request.form['_csrf_token']
        if crud_state != login_session['crud_state']:
            return "<script>function myFunction() {alert('CSRF attack detected!');}</script><body onload='myFunction()''>"

        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('deleteitem.html', item=itemToDelete, category=category, crud_state=login_session['crud_state'])


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

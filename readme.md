How to install:
1. Copy the folder itemcatalog into your vagrant machine /vagrant folder
2. run the virtual machine and SSH into the machine
3. run python database_setup.py
4. (optional) run python createsampleitem.py to create dummy data
5. run python main.py to run the server
6. using your browser, navigate to localhost:5000
7. to clean all data, run python clean.py
WARNING: running clean.py will delete all your data!

Rules:
1. You can only create a new category when you are logged in
2. You can only create/edit/delete items that you created
3. Login credentials use google+ accounts, create one if you havent


"""
Example SQLite Python Database
==============================

Experiment with the functions below to understand how the
database is created, data is inserted, and data is retrieved

"""
import sqlite3
from datetime import datetime


def create_db():
    """ Create table 'plants' in 'plant' database """
    try:
        conn = sqlite3.connect('plant.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE plants
                    (
                    name text,
                    date_planted text,
                    last_watered text,
                    nutrients_used text
                    )''')
        conn.commit()
        return True
    except BaseException:
        return False
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def get_date():
    """ Generate timestamp for data inserts """
    d = datetime.now()
    return d.strftime("%m/%d/%Y, %H:%M:%S")


def add_plant():
    """ Example data insert into plants table """
    new_plant_name = str(input("Please enter the name of your plant: "))  # Need exception handling
    new_plant_date = str(get_date())
    last_watered = str(get_date())
    nutrients_used = str(input("Did you use nutrients? y or n: "))  # Need to create valid input check
    data_to_insert = [(new_plant_name, new_plant_date, last_watered, nutrients_used)]
    try:
        conn = sqlite3.connect('plant.db')
        c = conn.cursor()
        c.executemany("INSERT INTO plants VALUES (?, ?, ?, ?)", data_to_insert)
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error. Tried to add duplicate record!")
    else:
        print("Success")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def query_db():
    """ Display all records in the plants table """
    try:
        conn = sqlite3.connect('plant.db')
        c = conn.cursor()
        for row in c.execute("SELECT * FROM plants"):
            print(row)
    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


create_db()  # Run create_db function first time to create the database
add_plant()  # Add a plant to the database (calling multiple times will add additional plants)
query_db()  # View all data stored in the

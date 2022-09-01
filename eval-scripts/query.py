from pymongo import MongoClient


client = MongoClient('mongodb://docker:mongopw@localhost:55000/')
colname = 'large-scale'
collection = client['microsurf'][colname]
query = {"framework": "wolfssl"}
collection.delete_many(query)
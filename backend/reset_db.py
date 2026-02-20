from app import app, Base, engine

with app.app_context():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("Database has been reset successfully!")
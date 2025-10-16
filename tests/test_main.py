from app.main import app

def test_home_route():
    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.json == {"message": "Hello from Flask CI pipeline!"}

from fastapi.testclient import TestClient

from tributario.api import app 

client = TestClient(app)

def test_autenticaco_200():
    response = client.post("/v1/autenticacao",
                        data={"username": "brayan", "password": "123"})
    assert response.status_code == 200


def test_autenticaco_404():
    response = client.post("/v1/autenticacao",
                        data={"username": "brayan", "password": "1234"})
    assert response.status_code == 404


def test_usuario_nao_autorizado():
    response = client.get("/teste")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_teste():
    response_autenticacao = client.post("/v1/autenticacao",
                        data={"username": "brayan", "password": "123"})
    token = response_autenticacao.json().get('access_token')
    token_bearer = 'Bearer ' + token
    response = client.get("/teste", headers={"Authorization": token_bearer})
    assert response.status_code == 200

from autenticacao import api

from fastapi import FastAPI

app = FastAPI()

app.include_router(api.router_autenticacao)
app.include_router(api.router_usuario)
app.include_router(api.router_usuarios_grupos)
app.include_router(api.router_usuarios_permissoes)
app.include_router(api.router_grupo)
app.include_router(api.router_grupos_permissoes)
app.include_router(api.router_permissao)

"""Comptes Keycloak des titulaires (identifiant = NIN), via le compte de service « issuer-backend ».

Le client confidentiel issuer-backend (créé par keycloak-init) porte les rôles realm-management
manage-users / view-users / query-users : l'issuer peut créer, activer/désactiver un compte et poser
un mot de passe initial temporaire (Keycloak impose de le changer à la première connexion).
Appels en direct sur http://keycloak:8080 (réseau Docker) : l'API d'administration n'est jamais exposée
par la passerelle.
"""
import secrets
import string
import time

import requests

from .config import get_settings


class KeycloakAdminError(RuntimeError):
    pass


_token: tuple[str, float] | None = None


def _base() -> str:
    s = get_settings()
    return f"{s.keycloak_internal_url.rstrip('/')}/admin/realms/{s.realm}"


def _access_token() -> str:
    global _token
    if _token and _token[1] > time.time() + 30:
        return _token[0]
    s = get_settings()
    if not s.issuer_backend_secret:
        raise KeycloakAdminError("ISSUER_BACKEND_SECRET non configuré : création des comptes impossible")
    try:
        r = requests.post(f"{s.keycloak_internal_url.rstrip('/')}/realms/{s.realm}/protocol/openid-connect/token",
                          data={"grant_type": "client_credentials", "client_id": s.issuer_backend_client_id,
                                "client_secret": s.issuer_backend_secret}, timeout=10)
    except requests.RequestException as e:
        raise KeycloakAdminError(f"Keycloak injoignable : {e}")
    if r.status_code != 200:
        raise KeycloakAdminError(f"Jeton du compte de service refusé ({r.status_code}) : {r.text[:200]}")
    j = r.json()
    _token = (j["access_token"], time.time() + j.get("expires_in", 60))
    return _token[0]


def _call(method: str, path: str, **kw) -> requests.Response:
    try:
        r = requests.request(method, _base() + path, headers={"Authorization": f"Bearer {_access_token()}"},
                             timeout=10, **kw)
    except requests.RequestException as e:
        raise KeycloakAdminError(f"Keycloak injoignable : {e}")
    if r.status_code >= 400:
        raise KeycloakAdminError(f"{method} {path} : {r.status_code} {r.text[:200]}")
    return r


def temporary_password() -> str:
    """Mot de passe initial lisible, à dicter ou remettre au titulaire (ex. « Kq7m-Xb3t-9Wza »)."""
    alphabet = "".join(c for c in string.ascii_letters + string.digits if c not in "0OoIl1")
    while True:
        p = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
        if any(c.isdigit() for c in p) and any(c.isupper() for c in p) and any(c.islower() for c in p):
            return p


def find_user(username: str) -> dict | None:
    users = _call("GET", "/users", params={"username": username, "exact": "true"}).json()
    return users[0] if users else None


def all_users() -> dict[str, dict]:
    """username -> représentation (pour la liste des citoyens)."""
    users = _call("GET", "/users", params={"max": 5000, "briefRepresentation": "true"}).json()
    return {u["username"]: u for u in users}


def ensure_user(nin: str, given_name: str, family_name: str, enabled: bool = True) -> tuple[dict, bool]:
    """Crée ou met à jour le compte du titulaire. Renvoie (utilisateur, créé ?)."""
    rep = {"username": nin, "enabled": enabled, "firstName": given_name, "lastName": family_name,
           # le profil utilisateur par défaut de Keycloak 26 exige un e-mail : adresse technique non routable
           "email": f"{nin}@citoyens.local", "emailVerified": True}
    u = find_user(nin)
    if u is None:
        _call("POST", "/users", json=rep)
        return find_user(nin), True
    _call("PUT", f"/users/{u['id']}", json={**u, **{k: v for k, v in rep.items() if k != "username"}})
    return find_user(nin), False


def set_temporary_password(user_id: str) -> str:
    pwd = temporary_password()
    _call("PUT", f"/users/{user_id}/reset-password", json={"type": "password", "value": pwd, "temporary": True})
    return pwd


def set_enabled(username: str, enabled: bool) -> bool:
    u = find_user(username)
    if u is None:
        return False
    _call("PUT", f"/users/{u['id']}", json={**u, "enabled": enabled})
    return True

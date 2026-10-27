import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import urllib.error
import urllib.request

import pandas as pd
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
import streamlit as st

st.set_page_config(page_title="TrustChain.AI", page_icon="🔐", layout="wide")
ITERATIONS_MDP = 600_000
NB_LIGNES_MAX = 200


class ConfigurationError(Exception):
    pass


def connexion():
    try:
        database_url = st.secrets["DATABASE_URL"]
    except (KeyError, FileNotFoundError) as exc:
        raise ConfigurationError(
            "Configurez DATABASE_URL dans les secrets Streamlit."
        ) from exc
    return psycopg.connect(database_url, row_factory=dict_row, connect_timeout=20)


def requete(sql, params=None):
    with connexion() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def hacher_mot_de_passe(mot_de_passe):
    sel = secrets.token_bytes(16)
    empreinte = hashlib.pbkdf2_hmac(
        "sha256", mot_de_passe.encode("utf-8"), sel, ITERATIONS_MDP
    )
    return "pbkdf2_sha256${}${}${}".format(
        ITERATIONS_MDP,
        base64.b64encode(sel).decode("ascii"),
        base64.b64encode(empreinte).decode("ascii"),
    )


def verifier_mot_de_passe(mot_de_passe, valeur_stockee):
    try:
        algo, iterations, sel, empreinte_attendue = valeur_stockee.split("$")
        if algo != "pbkdf2_sha256":
            return False
        empreinte = hashlib.pbkdf2_hmac(
            "sha256",
            mot_de_passe.encode("utf-8"),
            base64.b64decode(sel, validate=True),
            int(iterations),
        )
        return hmac.compare_digest(
            empreinte, base64.b64decode(empreinte_attendue, validate=True)
        )
    except (ValueError, TypeError):
        return False


def creer_compte(email, mot_de_passe):
    with connexion() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO utilisateur (email, mot_de_passe_hash)
               VALUES (%s, %s) RETURNING id_utilisateur, email""",
            (email, hacher_mot_de_passe(mot_de_passe)),
        )
        return cur.fetchone()


def trouver_compte(email):
    with connexion() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT id_utilisateur, email, mot_de_passe_hash
               FROM utilisateur WHERE email = %s""",
            (email,),
        )
        return cur.fetchone()


def page_connexion():
    st.title("TrustChain.AI")
    st.subheader("Connexion")
    connexion_tab, inscription_tab = st.tabs(["Se connecter", "Créer un compte"])

    with connexion_tab:
        with st.form("form_connexion"):
            email = st.text_input("Adresse e-mail", key="connexion_email").strip().lower()
            mot_de_passe = st.text_input(
                "Mot de passe", type="password", key="connexion_mdp"
            )
            soumettre = st.form_submit_button("Se connecter")
        if soumettre:
            compte = trouver_compte(email)
            if compte and verifier_mot_de_passe(
                mot_de_passe, compte["mot_de_passe_hash"]
            ):
                st.session_state["utilisateur"] = {
                    "id": compte["id_utilisateur"],
                    "email": compte["email"],
                }
                st.rerun()
            st.error("Adresse e-mail ou mot de passe incorrect.")

    with inscription_tab:
        with st.form("form_inscription", clear_on_submit=True):
            email = st.text_input("Adresse e-mail", key="inscription_email").strip().lower()
            mot_de_passe = st.text_input(
                "Mot de passe (12 caractères minimum)",
                type="password",
                key="inscription_mdp",
            )
            confirmation = st.text_input(
                "Confirmer le mot de passe",
                type="password",
                key="inscription_confirmation",
            )
            soumettre = st.form_submit_button("Créer mon compte")
        if soumettre:
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                st.error("Saisissez une adresse e-mail valide.")
            elif len(mot_de_passe) < 12:
                st.error("Le mot de passe doit contenir au moins 12 caractères.")
            elif mot_de_passe != confirmation:
                st.error("Les deux mots de passe ne correspondent pas.")
            else:
                try:
                    compte = creer_compte(email, mot_de_passe)
                except psycopg.errors.UniqueViolation:
                    st.error("Un compte existe déjà pour cette adresse e-mail.")
                else:
                    st.session_state["utilisateur"] = {
                        "id": compte["id_utilisateur"],
                        "email": compte["email"],
                    }
                    st.rerun()


def hote_autorise(hote, port):
    hote = hote.strip().rstrip(".").lower()
    valeur_autorisee = st.secrets.get("ALLOWED_DATABASE_HOSTS", [])
    if not isinstance(valeur_autorisee, (list, tuple)):
        valeur_autorisee = []
    hotes_autorises = {
        str(valeur).strip().rstrip(".").lower() for valeur in valeur_autorisee
    }
    if not hote or hote not in hotes_autorises:
        raise ValueError(
            "Cette base n’est pas autorisée. Demandez à l’administrateur "
            "d’ajouter son hôte à ALLOWED_DATABASE_HOSTS."
        )
    try:
        adresses = {
            resultat[4][0].split("%")[0]
            for resultat in socket.getaddrinfo(
                hote, port, type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror as exc:
        raise ValueError("L’hôte de la base est introuvable.") from exc
    if not adresses or any(
        not ipaddress.ip_address(adresse).is_global for adresse in adresses
    ):
        raise ValueError("L’hôte doit résoudre uniquement vers des adresses publiques.")
    return hote, sorted(adresses)[0]


def connexion_base_utilisateur(
    hote, adresse, port, nom_base, utilisateur, mot_de_passe
):
    return psycopg.connect(
        host=hote,
        hostaddr=adresse,
        port=port,
        dbname=nom_base,
        user=utilisateur,
        password=mot_de_passe,
        sslmode="verify-full",
        connect_timeout=10,
        options="-c statement_timeout=10000 -c idle_in_transaction_session_timeout=10000",
    )


def lire_schema(conn):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("""
                SELECT table_schema, table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                ORDER BY table_schema, table_name, ordinal_position
                LIMIT 500
            """)
            lignes = cur.fetchall()
    tables = {}
    for schema, table, colonne, type_donnee in lignes:
        tables.setdefault(f"{schema}.{table}", []).append(
            f"{colonne} ({type_donnee})"
        )
    if not tables:
        raise ValueError("Aucune table lisible n’a été trouvée dans cette base.")
    return "\n".join(
        f"{table}: {', '.join(colonnes)}" for table, colonnes in tables.items()
    )


def generer_sql_openai(cle_api, question, schema):
    contenu = {
        "model": "gpt-4o-mini",
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "Convertis la question en une seule requête PostgreSQL "
                    "SELECT en lecture seule, fondée uniquement sur le schéma "
                    "fourni. N'utilise ni point-virgule, ni commande de "
                    "modification, ni fonction d'écriture. Retourne uniquement "
                    "un objet JSON avec une propriété string « sql »."
                ),
            },
            {
                "role": "user",
                "content": f"Schéma disponible:\n{schema}\n\nQuestion:\n{question}",
            },
        ],
    }
    requete_http = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(contenu).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {cle_api}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(requete_http, timeout=30) as reponse:
            resultat = json.loads(reponse.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"OpenAI a refusé la requête (HTTP {exc.code}). Vérifiez votre clé API."
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Impossible de joindre l’API OpenAI.") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("La réponse de l’API OpenAI est invalide.") from exc
    try:
        sql = json.loads(resultat["choices"][0]["message"]["content"])["sql"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("OpenAI n’a pas fourni de requête SQL exploitable.") from exc
    if (
        not isinstance(sql, str)
        or not re.match(r"(?is)^\s*(SELECT|WITH)\b", sql)
        or ";" in sql
    ):
        raise RuntimeError("La requête générée n’est pas une requête unique valide.")
    return sql.strip()


def executer_sql_lecture_seule(conn, sql):
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(sql, prepare=True)
            if cur.description is None:
                raise ValueError("La requête n’a pas renvoyé de tableau de résultats.")
            colonnes = [description.name for description in cur.description]
            lignes = cur.fetchmany(NB_LIGNES_MAX + 1)
    tronque = len(lignes) > NB_LIGNES_MAX
    lignes = lignes[:NB_LIGNES_MAX]
    resultat = {
        "colonnes": colonnes,
        "lignes": [dict(zip(colonnes, ligne)) for ligne in lignes],
        "tronque": tronque,
    }
    return json.loads(json.dumps(resultat, default=str))


def enregistrer_question(id_utilisateur, question, nom_base, sql, resultat):
    with connexion() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO requete_utilisateur
                   (id_utilisateur, question, nom_base, sql_genere, resultat_json)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING id_requete""",
            (id_utilisateur, question, nom_base, sql, Jsonb(resultat)),
        )
        return cur.fetchone()["id_requete"]


def page_nouvelle_question(utilisateur):
    st.header("Poser une question à ma base")
    st.caption(
        "Connexion PostgreSQL personnelle, requête en lecture seule. "
        "Les identifiants de base et la clé OpenAI ne sont pas enregistrés."
    )
    st.warning(
        "Le schéma de la base et votre question seront envoyés à OpenAI. "
        "La question, le SQL généré et le résultat (200 lignes maximum) "
        "seront conservés dans votre espace TrustChain.AI."
    )
    with st.form("form_question", clear_on_submit=True):
        hote = st.text_input("Hôte PostgreSQL")
        port = st.number_input("Port", min_value=1, max_value=65535, value=5432)
        nom_base = st.text_input("Nom de la base")
        utilisateur_db = st.text_input("Identifiant PostgreSQL")
        mot_de_passe_db = st.text_input(
            "Mot de passe PostgreSQL", type="password"
        )
        cle_api = st.text_input("Votre clé API OpenAI", type="password")
        question = st.text_area(
            "Votre question",
            max_chars=2000,
            placeholder="Ex. Quel est le chiffre d’affaires par région ce trimestre ?",
        )
        consentement = st.checkbox(
            "J’accepte l’envoi de ma question et du schéma à OpenAI."
        )
        soumettre = st.form_submit_button("Analyser")
    if not soumettre:
        return
    if not all(
        (
            hote.strip(),
            nom_base.strip(),
            utilisateur_db.strip(),
            mot_de_passe_db,
            cle_api.strip(),
            question.strip(),
        )
    ):
        st.error("Tous les champs sont obligatoires.")
        return
    if not consentement:
        st.error("Le consentement à l’envoi à OpenAI est nécessaire.")
        return
    try:
        hote_valide, adresse = hote_autorise(hote, int(port))
        with connexion_base_utilisateur(
            hote_valide,
            adresse,
            int(port),
            nom_base.strip(),
            utilisateur_db.strip(),
            mot_de_passe_db,
        ) as conn:
            schema = lire_schema(conn)
        sql = generer_sql_openai(cle_api.strip(), question.strip(), schema)
        with connexion_base_utilisateur(
            hote_valide,
            adresse,
            int(port),
            nom_base.strip(),
            utilisateur_db.strip(),
            mot_de_passe_db,
        ) as conn:
            resultat = executer_sql_lecture_seule(conn, sql)
        id_requete = enregistrer_question(
            utilisateur["id"], question.strip(), nom_base.strip(), sql, resultat
        )
    except (ValueError, RuntimeError) as exc:
        st.error(str(exc))
        return
    except psycopg.Error:
        st.error(
            "Connexion ou requête PostgreSQL impossible. Vérifiez les accès, "
            "le certificat TLS, le schéma et les permissions en lecture seule."
        )
        return
    st.success(f"Analyse enregistrée dans votre espace (#{id_requete}).")
    st.code(sql, language="sql")
    if resultat["lignes"]:
        st.dataframe(
            pd.DataFrame(resultat["lignes"]), width="stretch", hide_index=True
        )
    else:
        st.info("La requête n’a renvoyé aucune ligne.")
    if resultat["tronque"]:
        st.caption(f"Affichage limité aux {NB_LIGNES_MAX} premières lignes.")


def page_mes_questions(utilisateur):
    st.header("Mes questions")
    with connexion() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT id_requete, question, nom_base, sql_genere,
                      resultat_json, date_creation
               FROM requete_utilisateur
               WHERE id_utilisateur = %s
               ORDER BY date_creation DESC""",
            (utilisateur["id"],),
        )
        lignes = cur.fetchall()
    if not lignes:
        st.info("Vous n’avez pas encore posé de question.")
        return
    par_id = {ligne["id_requete"]: ligne for ligne in lignes}
    choix = st.selectbox(
        "Analyse",
        list(par_id),
        format_func=lambda i: (
            f"#{i} - {par_id[i]['date_creation']:%Y-%m-%d %H:%M} - "
            f"{par_id[i]['question'][:70]}"
        ),
    )
    analyse = par_id[choix]
    st.write(f"**Question :** {analyse['question']}")
    st.caption(f"Base : {analyse['nom_base']} | {analyse['date_creation']}")
    st.code(analyse["sql_genere"], language="sql")
    resultat = analyse["resultat_json"]
    if resultat["lignes"]:
        st.dataframe(
            pd.DataFrame(resultat["lignes"]), width="stretch", hide_index=True
        )
    else:
        st.info("Cette requête n’a renvoyé aucune ligne.")
    if resultat["tronque"]:
        st.caption(f"Résultat limité aux {NB_LIGNES_MAX} premières lignes.")


def page_demo():
    st.header("Démonstration")
    st.caption("Exécutions fictives partagées, sans données de vos bases personnelles.")
    nb = requete("SELECT COUNT(*) AS n FROM execution")[0]["n"]
    st.metric("Nombre d'exécutions de démonstration", nb)
    st.subheader("Analyses récentes")
    lignes = requete("""
        SELECT id_exec, question_humaine, statut, date_execution
        FROM execution
        ORDER BY date_execution DESC
        LIMIT 10
    """)
    st.dataframe(pd.DataFrame(lignes), width="stretch", hide_index=True)


utilisateur = st.session_state.get("utilisateur")
if utilisateur is None:
    try:
        page_connexion()
    except ConfigurationError as exc:
        st.error(str(exc))
    except psycopg.Error:
        st.error(
            "La base TrustChain.AI n’est pas prête. Vérifiez DATABASE_URL "
            "et exécutez le script trustchain_ai_postgresql.sql."
        )
    st.stop()

st.title("TrustChain.AI")
st.sidebar.write(f"Connecté : **{utilisateur['email']}**")
if st.sidebar.button("Se déconnecter"):
    del st.session_state["utilisateur"]
    st.rerun()

page = st.sidebar.radio(
    "Navigation",
    ["Nouvelle question", "Mes questions", "Démonstration"],
)

try:
    if page == "Nouvelle question":
        page_nouvelle_question(utilisateur)
    elif page == "Mes questions":
        page_mes_questions(utilisateur)
    else:
        page_demo()
except ConfigurationError as exc:
    st.error(str(exc))
except psycopg.Error:
    st.error(
        "Erreur de base de données. Vérifiez la connexion TrustChain.AI "
        "et l’installation du schéma PostgreSQL."
    )

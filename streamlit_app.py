import os
import secrets  # To generate a random `state` value

from streamlit_cookies_manager import EncryptedCookieManager
import streamlit as st
from authlib.integrations.requests_client import OAuth2Session
import requests


# Load GitHub OAuth details from environment variables
GITHUB_CLIENT_ID = os.environ["GH_CLIENT_ID"]
GITHUB_CLIENT_SECRET = os.environ["GH_CLIENT_SECRET"]
# The same as your GitHub OAuth redirect URI
REDIRECT_URI = "https://gh-app-demo.streamlit.app/"
ORG_NAME = "developmentseed"  # The organization you want to check membership for

cookies = EncryptedCookieManager(
    # This prefix will get added to all your cookie names.
    # This way you can run your app on Streamlit Cloud without cookie name clashes with other apps.
    prefix=REDIRECT_URI,
    # We encrypt the cookie with our client secret.
    password=GITHUB_CLIENT_SECRET,
)
if not cookies.ready():
    # Wait for the component to load and send us current cookies.
    st.stop()


def get_oauth_client():
    """ OAuth2 client session """
    return OAuth2Session(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, redirect_uri=REDIRECT_URI)


def get_github_auth_url():
    """ Get GitHub authorization URL with a random `state` value """
    oauth_client = get_oauth_client()

    # Generate a random `state` value and store it in Streamlit session state
    state = secrets.token_urlsafe(16)
    cookies['oauth_state'] = state
    cookies.save()

    authorization_url, _ = oauth_client.create_authorization_url(
        "https://github.com/login/oauth/authorize",
        state=state,  # Include the `state` parameter
        scope="read:org user:email"  # Need read:org to check membership
    )
    return authorization_url


def get_access_token(code, state):
    """ Get access token from GitHub """
    oauth_client = get_oauth_client()

    # Verify that the `state` from the redirect matches the stored `state`
    if state != cookies.get('oauth_state'):
        st.error("State mismatch: Potential CSRF attack detected.")
        return None

    token = oauth_client.fetch_token(
        "https://github.com/login/oauth/access_token",
        code=code,
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET
        # redirect_uri=
    )
    return token


def get_github_user_info(token):
    """ Fetch user information from GitHub """
    headers = {'Authorization': f'token {token}'}
    response = requests.get("https://api.github.com/user", headers=headers)
    return response.json()


def is_user_in_org(token, org_name, username):
    """ Check if user is a member of the organization """
    headers = {'Authorization': f'token {token}'}
    response = requests.get(
        f"https://api.github.com/orgs/{org_name}/memberships/{username}", headers=headers)
    return response.status_code == 200


# Streamlit UI
st.title("GitHub OAuth SSO Login")

# Check if the 'code' is present in the query params after GitHub redirects back
if code := st.query_params.get("code"):
    # Extract the state from query params
    state = st.query_params.get("state", None)

    # Exchange the code for an access token
    token = get_access_token(code, state)

    if token:
        # Clear query params
        st.query_params.clear()

        # Fetch user info
        user_info = get_github_user_info(token['access_token'])

        # Check if the user is a member of the organization
        if is_user_in_org(token['access_token'], ORG_NAME, user_info['login']):
            st.success(f"Welcome {user_info['login']}")
            st.image(user_info['avatar_url'])
        else:
            st.error(
                f"Access denied: {user_info['login']} is not a member of the {ORG_NAME} organization.")
else:
    # Display login button
    auth_url = get_github_auth_url()
    st.markdown(f"[Login with GitHub]({auth_url})")
    # st.markdown(f'Please <a href="{auth_url}" target="_self">Login with GitHub</a>', unsafe_allow_html=True)

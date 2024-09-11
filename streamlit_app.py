import os
import secrets  # To generate a random `state` value
from datetime import datetime, timedelta

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
cookies._cookie_manager._default_expiry = datetime.now() + timedelta(days=1)
if not cookies.ready():
    # Wait for the component to load and send us current cookies.
    st.stop()

oauth_client = OAuth2Session(
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    redirect_uri=REDIRECT_URI
)


def get_github_auth_url():
    """ Get GitHub authorization URL with a random `state` value """

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
    # Verify that the `state` from the redirect matches the stored `state`
    st.markdown(f'{state=}')
    st.markdown(f"{cookies.get('oauth_state')=}")
    if state != cookies.get('oauth_state'):
        st.error("State mismatch: Potential CSRF attack detected.")
        return None

    return oauth_client.fetch_token(
        "https://github.com/login/oauth/access_token",
        code=code,
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET
        # redirect_uri=
    )


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


# Views
def home(user_info):
    st.success(f"Welcome {user_info['login']}")
    st.image(user_info['avatar_url'])


def oauth_callback(code: str, state: str):
    # Clear query params
    st.query_params.clear()

    # Exchange the code for an access token
    token = get_access_token(code, state)

    # Fetch user info
    user_info = get_github_user_info(token['access_token'])

    # Check if the user is a member of the organization
    if is_user_in_org(token['access_token'], ORG_NAME, user_info['login']):
        # Persist
        cookies['token'] = token
        cookies['user_info'] = user_info
    else:
        st.error(
            f"Access denied: {user_info['login']} is not a member of the {ORG_NAME} organization.")


def login_view():
    # Display login button
    auth_url = get_github_auth_url()
    st.markdown(f"[Login with GitHub]({auth_url})")


# App
# Streamlit UI
st.title("GitHub OAuth SSO Login")

# If we have a user, we're logged in...
if user_info := cookies.get('user_info'):
    home(user_info)

# Check if the 'code' is present in the query params after GitHub redirects back
elif code := st.query_params.get("code"):
    # Extract the state from query params
    state = st.query_params.get("state", None)
    oauth_callback(code, state)

# Handle unauthenticad
else:
    login_view()

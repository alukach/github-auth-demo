import streamlit as st
from authlib.integrations.requests_client import OAuth2Session
import os
import requests
import secrets  # To generate a random `state` value

# Load GitHub OAuth details from environment variables
GITHUB_CLIENT_ID = os.getenv("GH_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GH_CLIENT_SECRET")
REDIRECT_URI = "https://gh-app-demo.streamlit.app/"  # The same as your GitHub OAuth redirect URI
ORG_NAME = "developmentseed"  # The organization you want to check membership for

# OAuth2 client session
def get_oauth_client():
    return OAuth2Session(GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, redirect_uri=REDIRECT_URI)

# Get GitHub authorization URL with a random `state` value
def get_github_auth_url():
    oauth_client = get_oauth_client()
    
    # Generate a random `state` value and store it in Streamlit session state
    state = secrets.token_urlsafe(16)
    st.session_state['oauth_state'] = state
    
    authorization_url, _ = oauth_client.create_authorization_url(
        "https://github.com/login/oauth/authorize",
        state=state,  # Include the `state` parameter
        scope="read:org user:email"  # Need read:org to check membership
    )
    return authorization_url

# Get access token from GitHub
def get_access_token(code, state):
    oauth_client = get_oauth_client()
    
    # Verify that the `state` from the redirect matches the stored `state`
    # if state != st.session_state.get('oauth_state'):
    #     st.error("State mismatch: Potential CSRF attack detected.")
    #     return None
    
    token = oauth_client.fetch_token(
        "https://github.com/login/oauth/access_token",
        code=code,
        client_secret=GITHUB_CLIENT_SECRET
    )
    return token

# Fetch user information from GitHub
def get_github_user_info(token):
    headers = {'Authorization': f'token {token}'}
    response = requests.get("https://api.github.com/user", headers=headers)
    return response.json()

# Check if user is a member of the organization
def is_user_in_org(token, org_name, username):
    headers = {'Authorization': f'token {token}'}
    response = requests.get(f"https://api.github.com/orgs/{org_name}/memberships/{username}", headers=headers)
    return response.status_code == 200

# Streamlit UI
st.title("GitHub OAuth SSO Login")

# Check if the 'code' is present in the query params after GitHub redirects back
if code := st.query_params.get("code"):
    state = st.query_params.get("state", None)  # Extract the state from query params
    
    token = get_access_token(code, state)  # Exchange the code for an access token
    
    if token:
        user_info = get_github_user_info(token['access_token'])  # Fetch user info

        # Check if the user is a member of the organization
        if is_user_in_org(token['access_token'], ORG_NAME, user_info['login']):
            st.success(f"Welcome {user_info['login']}")
            st.image(user_info['avatar_url'])
        else:
            st.error(f"Access denied: {user_info['login']} is not a member of the {ORG_NAME} organization.")
else:
    # Display login button
    auth_url = get_github_auth_url()
    st.markdown(f'Please <a href="{auth_url}" target="_self">Login with GitHub</a>')
